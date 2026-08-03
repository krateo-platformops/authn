package strategies

import "github.com/krateo-platformops/authn/apis/core"

const (
	defaultLoginText       = "Login with "
	defaultBackgroundColor = "#ffffff"
	defaultTextColor       = "#000000"
	defaultIcon            = "key"
)

func getDefaultGraphicsObject(authName string) *core.Graphics {
	return &core.Graphics{
		Icon:            defaultIcon,
		DisplayName:     defaultLoginText + authName,
		BackgroundColor: defaultBackgroundColor,
		TextColor:       defaultTextColor,
	}
}
