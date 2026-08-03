package encode

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/krateo-platformops/authn/internal/helpers/userinfo"
	"github.com/krateo-platformops/plumbing/jwtutil"
)

type Extras struct {
	UserInfo    userinfo.Info
	JwtDuration time.Duration
	JwtSingKey  string
}

func Success(w http.ResponseWriter, dat []byte, extras *Extras) (err error) {
	out := response{
		Data: dat,
	}

	if extras != nil {
		if nfo := extras.UserInfo; nfo != nil {
			out.User = &user{
				Username:    nfo.GetUserName(),
				DisplayName: nfo.GetExtensions().Get("name"),
				AvatarURL:   nfo.GetExtensions().Get("avatarUrl"),
			}
			out.Groups = nfo.GetGroups()

			if extras.JwtSingKey != "" {
				if extras.JwtDuration <= 0 {
					extras.JwtDuration = time.Hour * 8
				}

				out.AccessToken, err = jwtutil.CreateToken(jwtutil.CreateTokenOptions{
					Username:   nfo.GetUserName(),
					Groups:     nfo.GetGroups(),
					Duration:   extras.JwtDuration,
					SigningKey: extras.JwtSingKey,
				})
				if err != nil {
					return err
				}
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	return json.NewEncoder(w).Encode(&out)
}

type user struct {
	DisplayName string `json:"displayName"`
	Username    string `json:"username"`
	AvatarURL   string `json:"avatarURL"`
}

type response struct {
	AccessToken string          `json:"accessToken,omitempty"`
	User        *user           `json:"user,omitempty"`
	Groups      []string        `json:"groups,omitempty"`
	Data        json.RawMessage `json:"data,omitempty"`
}
