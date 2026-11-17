{{/*
Expand the name of the chart.
*/}}
{{- define "authn.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "authn.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "authn.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "authn.labels" -}}
helm.sh/chart: {{ include "authn.chart" . }}
{{ include "authn.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "authn.selectorLabels" -}}
app.kubernetes.io/name: {{ include "authn.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
The ServiceAccount authn runs as, and the one its RoleBinding and
ClusterRoleBindings name: the pod and its RBAC must agree, or CSR approval and
TokenReview fail with 403. With serviceAccount.create false a name is required:
the chart won't bind authn's rights (CSR approval, the kube-apiserver-client
signer, TokenReview) to the namespace's "default" ServiceAccount, which every
pod without one of its own runs as.
*/}}
{{- define "authn.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "authn.fullname" .) .Values.serviceAccount.name }}
{{- else if .Values.serviceAccount.name }}
{{- .Values.serviceAccount.name }}
{{- else }}
{{- fail "serviceAccount.name is required when serviceAccount.create is false: the chart binds authn's RBAC to it, and won't bind it to the namespace's default ServiceAccount" }}
{{- end }}
{{- end }}

{{/*
Fully-qualified image reference, honoring an optional global.imageRegistry override.
The registry host (.img.registry) is replaced by .Values.global.imageRegistry when that is set, so
a single value relocates EVERY image for a mirror / air-gapped install. Repository paths are
preserved, matching how registry replication mirrors by default. Canonical helper — identical
across all Krateo charts (shipped from the shared chart scaffold).
*/}}
{{- define "krateo.image" -}}
{{- $g := .global | default dict -}}
{{- $registry := $g.imageRegistry | default .img.registry -}}
{{- $tag := .img.tag | default .defaultTag -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry .img.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" .img.repository $tag -}}
{{- end -}}
{{- end -}}

{{/*
Verification-only JWT keys of a key rotation (jwt.previousKeys), as the
JWT_PREVIOUS_KEYS value: comma-separated kid=path. Entry i is mounted under
/etc/authn/jwt-previous/<i>/. The default list applies in the template because
the installer builds values without this chart's values.yaml.
*/}}
{{- define "authn.jwtPreviousKeys" -}}
{{- $out := list -}}
{{- range $i, $k := (.Values.jwt.previousKeys | default list) -}}
{{- $key := $k.secretKey | default "private.pem" -}}
{{- $out = append $out (printf "%s=/etc/authn/jwt-previous/%d/%s" $k.kid $i $key) -}}
{{- end -}}
{{- join "," $out -}}
{{- end -}}
