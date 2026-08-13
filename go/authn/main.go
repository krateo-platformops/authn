package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/krateo-platformops/authn/internal/env"
	kubeconfig "github.com/krateo-platformops/authn/internal/helpers/kube/config"
	"github.com/krateo-platformops/authn/internal/helpers/kube/util"
	"github.com/krateo-platformops/authn/internal/helpers/restaction"
	"github.com/krateo-platformops/authn/internal/middlewares/cors"
	"github.com/krateo-platformops/authn/internal/routes"
	"github.com/krateo-platformops/authn/internal/routes/auth/basic"
	"github.com/krateo-platformops/authn/internal/routes/auth/info"
	"github.com/krateo-platformops/authn/internal/routes/auth/ldap"
	"github.com/krateo-platformops/authn/internal/routes/auth/oauth"
	"github.com/krateo-platformops/authn/internal/routes/auth/oidc"
	"github.com/krateo-platformops/authn/internal/routes/auth/serviceaccount"
	"github.com/krateo-platformops/authn/internal/routes/auth/strategies"
	"github.com/krateo-platformops/authn/internal/routes/health"
	"github.com/krateo-platformops/authn/internal/routes/jwks"
	"github.com/krateo-platformops/authn/internal/telemetry"
	xcontext "github.com/krateo-platformops/plumbing/context"
	"github.com/krateo-platformops/plumbing/jwtutil"
	"github.com/krateo-platformops/plumbing/signup"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	serviceName = "auth"
)

var (
	Version string
	Build   string
)

func main() {
	// Flags
	kconfig := flag.String(clientcmd.RecommendedConfigPathFlag, "", "absolute path to the kubeconfig file")
	debugOn := flag.Bool("debug", env.Bool("AUTHN_DEBUG", false), "dump verbose output")
	dumpEnv := flag.Bool("dump-env", env.Bool("AUTHN_DUMP_ENV", false), "dump environment variables")
	corsOn := flag.Bool("cors", env.Bool("AUTHN_CORS", true), "enable or disable CORS")
	otelTracingOn := flag.Bool("otel-tracing", telemetry.TracingEnabled(),
		"enable OpenTelemetry tracing (OTLP/HTTP); defaults to OTEL_TRACING_ENABLED, which defaults to OTEL_ENABLED; default off")
	servicePort := flag.Int("port", env.Int("AUTHN_PORT", 8082), "port to listen on")
	certExpiresIn := flag.Duration("cert-expires",
		env.Duration("AUTHN_KUBECONFIG_CRT_EXPIRES_IN", time.Hour*24), "generated certificate duration (default: 24h)")

	clusterName := flag.String("kubeconfig-cluster-name",
		env.String("AUTHN_KUBECONFIG_CLUSTER_NAME", "krateo"), "cluster name for generated kubeconfig")
	kubernetesURL := flag.String("kubeconfig-server-url",
		env.String("AUTHN_KUBECONFIG_SERVER_URL", ""), "kubernetes api server url for generated kubeconfig")
	snowplowHOST := flag.String("snowplow-host",
		env.String("SNOWPLOW_SERVICE_HOST", ""), "snowplow host for restaction api calls")
	snowplowPORT := flag.String("snowplow-post",
		env.String("SNOWPLOW_SERVICE_PORT", "8081"), "snowplow port for restaction api calls")
	var snowplowURL *string
	temp := "http://" + *snowplowHOST + ":" + *snowplowPORT
	snowplowURL = &temp
	if *snowplowURL == "http://:8081" {
		snowplowURL = flag.String("snowplow-url", env.String("URL_SNOWPLOW", "http://snowplow.krateo-system.svc.cluster.local:8081"), "snowplow url for restaction api calls")
	}
	storageNamespace := flag.String("namespace",
		env.String("AUTHN_NAMESPACE", ""), "namespace where to store secrets with generated config")
	authnUsername := flag.String("authn-username",
		env.String("AUTHN_USERNAME", "authn"), "authn username for clientconfig for restaction api calls")
	signKeyFile := flag.String("jwt-sign-key-file", env.String("JWT_SIGN_KEY_FILE", ""), "path to the PEM-encoded RSA private key used to sign JWT tokens (mounted from a Secret)")
	jwtKeyID := flag.String("jwt-kid", env.String("JWT_KID", ""), "key ID (kid) set in the JWT header; must match the kid published in the JWKS")
	serviceAccountAudience := flag.String("serviceaccount-audience",
		env.String("AUTHN_SERVICEACCOUNT_AUDIENCE", serviceaccount.DefaultAudience),
		"audience the projected ServiceAccount token must carry for the /serviceaccount/login strategy")

	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Flags:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if len(*storageNamespace) > 0 {
		os.Setenv(util.NamespaceEnvVar, *storageNamespace)
	}

	// Initialize the logger
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Default level for this log is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if *debugOn {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	log := zerolog.New(os.Stdout).With().
		Str("service", serviceName).
		Timestamp().
		Logger()

	if log.Debug().Enabled() {
		evt := log.Debug().
			Str("version", Version).
			Str("build", Build).
			Str("debug", fmt.Sprintf("%t", *debugOn)).
			Str("cors", fmt.Sprintf("%t", *corsOn)).
			Str("port", fmt.Sprintf("%d", *servicePort)).
			Str("clusterName", *clusterName).
			Str("kubernetesURL", *kubernetesURL).
			Dur("certExpire", *certExpiresIn)

		if *dumpEnv {
			evt = evt.Strs("env-vars", os.Environ())
		}

		evt.Msg("configuration and env vars info")
	}

	log.Debug().Msgf("Snowplow URL from Service ENV: %s", temp)
	log.Debug().Msgf("Snowplow URL computed/from parameter: %s", *snowplowURL)

	// OpenTelemetry (default OFF). The master gate is OTEL_ENABLED; tracing and
	// metrics each default to it and can be overridden per-signal via
	// OTEL_TRACING_ENABLED / OTEL_METRICS_ENABLED. The --otel-tracing flag
	// (default OTEL_TRACING_ENABLED, which itself defaults to OTEL_ENABLED)
	// continues to drive the tracing pipeline: when it resolves true, reflect
	// that into the env the telemetry package reads (the flag may have been set
	// explicitly on the CLI).
	if *otelTracingOn {
		os.Setenv(telemetry.EnvTracingEnabled, "true")
	}
	otelShutdown, err := telemetry.Setup(context.Background(), serviceName, Version)
	if err != nil {
		log.Fatal().Err(err).Msg("initializing OpenTelemetry")
	}
	if telemetry.TracingEnabled() || telemetry.MetricsEnabled() {
		log.Info().
			Bool("tracing", telemetry.TracingEnabled()).
			Bool("metrics", telemetry.MetricsEnabled()).
			Msg("OpenTelemetry enabled")
	}

	// Kubernetes configuration
	var cfg *rest.Config
	if len(*kconfig) > 0 {
		cfg, err = clientcmd.BuildConfigFromFlags("", *kconfig)
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		log.Fatal().Err(err).Msg("resolving kubeconfig for rest client")
	}

	gen := kubeconfig.NewGenerator(cfg,
		kubeconfig.KubernetesURL(*kubernetesURL),
		kubeconfig.CertDuration(*certExpiresIn),
		kubeconfig.ClusterName(*clusterName),
		kubeconfig.Log(log),
	)

	// JWT signing key: an RSA private key, PEM-encoded, mounted from a Secret.
	// The matching public key must be published in the JWKS under *jwtKeyID.
	if *jwtKeyID == "" {
		log.Fatal().Msg("JWT key ID must be set (--jwt-kid / JWT_KID)")
	}
	pemBytes, err := os.ReadFile(*signKeyFile)
	if err != nil {
		log.Fatal().Err(err).Msg("reading JWT signing key file")
	}
	privateKey, err := jwtutil.ParseRSAPrivateKeyFromPEM(pemBytes)
	if err != nil {
		log.Fatal().Err(err).Msg("parsing JWT signing key")
	}

	healthy := int32(0)

	all := []routes.Route{}
	all = append(all, strategies.List(cfg))
	all = append(all, info.Info(cfg))
	all = append(all, health.Check(&healthy, Version, serviceName))
	all = append(all, jwks.Endpoint(&privateKey.PublicKey, *jwtKeyID))

	all = append(all, basic.Login(cfg, basic.LoginOptions{
		KubeconfigGenerator: gen,
		JwtDuration:         *certExpiresIn,
		JwtPrivateKey:       privateKey,
		JwtKeyID:            *jwtKeyID,
	}))

	// Kubernetes intra-service auth: backend services exchange their own (audience-bound)
	// ServiceAccount token (validated via TokenReview) for an authn JWT + clientconfig.
	all = append(all, serviceaccount.Login(cfg, serviceaccount.LoginOptions{
		KubeconfigGenerator: gen,
		JwtDuration:         *certExpiresIn,
		JwtPrivateKey:       privateKey,
		JwtKeyID:            *jwtKeyID,
		Audience:            *serviceAccountAudience,
	}))

	all = append(all, ldap.Login(cfg, ldap.LoginOptions{
		KubeconfigGenerator: gen,
		JwtDuration:         *certExpiresIn,
		JwtPrivateKey:       privateKey,
		JwtKeyID:            *jwtKeyID,
	}))

	accessToken, err := jwtutil.CreateToken(jwtutil.CreateTokenOptions{
		Username:   *authnUsername,
		Groups:     []string{"authn"},
		KeyID:      *jwtKeyID,
		PrivateKey: privateKey,
		Duration:   time.Hour * 8760, // 1 year,
	})
	if err != nil {
		log.Fatal().Err(err).Msgf("cannot create jwt token for %s", *authnUsername)
	}

	all = append(all, oauth.Login(
		xcontext.BuildContext(context.Background(),
			xcontext.WithAccessToken(accessToken),
			func(ctx context.Context) context.Context {
				ctx = context.WithValue(ctx,
					restaction.RestActionContextKey("username"), *authnUsername)
				return context.WithValue(ctx,
					restaction.RestActionContextKey("snowplowURL"), *snowplowURL)
			},
		), cfg, oauth.LoginOptions{
			KubeconfigGenerator: gen,
			JwtDuration:         *certExpiresIn,
			JwtPrivateKey:       privateKey,
			JwtKeyID:            *jwtKeyID,
		}))

	all = append(all, oidc.Login(
		xcontext.BuildContext(context.Background(),
			xcontext.WithAccessToken(accessToken),
			func(ctx context.Context) context.Context {
				ctx = context.WithValue(ctx,
					restaction.RestActionContextKey("username"), *authnUsername)
				return context.WithValue(ctx,
					restaction.RestActionContextKey("snowplowURL"), *snowplowURL)
			},
		), cfg, oidc.LoginOptions{
			KubeconfigGenerator: gen,
			JwtDuration:         *certExpiresIn,
			JwtPrivateKey:       privateKey,
			JwtKeyID:            *jwtKeyID,
		}))

	var handler http.Handler = routes.Serve(all, log)

	// OpenTelemetry HTTP server instrumentation (gated, default OFF). When
	// metrics are opted in, emit http.server.* instruments; when tracing is
	// opted in, wrap with otelhttp so each inbound request becomes a server
	// span (named by URL path) and traceparent is extracted. /health is
	// filtered out of tracing to avoid probe noise. When both are off, the
	// handler chain is left untouched (byte-identical off-path).
	if telemetry.MetricsEnabled() {
		handler = telemetry.MetricsMiddleware(handler)
	}
	if telemetry.TracingEnabled() {
		handler = otelhttp.NewHandler(handler, serviceName,
			otelhttp.WithSpanNameFormatter(func(_ string, r *http.Request) string {
				return r.URL.Path
			}),
			otelhttp.WithFilter(func(r *http.Request) bool {
				return r.URL.Path != health.Path
			}),
		)
	}

	if *corsOn {
		c := cors.New(cors.Options{
			AllowedOrigins: []string{"*"},
			AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			// traceparent/tracestate/baggage are REQUIRED so the cross-origin
			// browser->authn hop can carry W3C trace context to authn.
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Auth-Code", "traceparent", "tracestate", "baggage"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300, // Maximum value not ignored by any of major browsers
		})

		handler = c.Handler(handler)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *servicePort),
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 50 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), []os.Signal{
		os.Interrupt,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGKILL,
		syscall.SIGHUP,
		syscall.SIGQUIT,
	}...)
	defer stop()

	// Create authn clientconfig to call snowplow's RESTActions
	_, _ = signup.Do(context.TODO(), signup.Options{
		RestConfig:   cfg,
		Namespace:    *storageNamespace,
		CAData:       string(cfg.CAData),
		ServerURL:    *kubernetesURL,
		CertDuration: time.Hour * 8760, // 1 year
		Username:     *authnUsername,
		UserGroups:   []string{"authn"},
	})

	go func() {
		atomic.StoreInt32(&healthy, 1)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msgf("could not listen on %s", server.Addr)
		}
	}()

	// Listen for the interrupt signal.
	log.Info().Msgf("server is ready to handle requests at @ %s", server.Addr)
	<-ctx.Done()

	// Restore default behavior on the interrupt signal and notify user of shutdown.
	stop()
	log.Info().Msg("server is shutting down gracefully, press Ctrl+C again to force")
	atomic.StoreInt32(&healthy, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Flush and release OpenTelemetry providers (no-op when telemetry is off).
	if err := otelShutdown(ctx); err != nil {
		log.Err(err).Msg("error shutting down OpenTelemetry")
	}

	server.SetKeepAlivesEnabled(false)
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal().Err(err).Msg("server forced to shutdown")
	}

	log.Info().Msg("server gracefully stopped")
}
