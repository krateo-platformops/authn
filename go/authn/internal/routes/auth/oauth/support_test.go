package oauth

import (
	"fmt"
	"testing"

	"github.com/rs/zerolog/log"
)

// No tests for code -> token exchange because it's done through the oauth2 library

func TestConfigUpdate(t *testing.T) {
	dataOk := make(map[string]interface{})
	dataFailureEmail := make(map[string]interface{})
	dataFailureGroup := make(map[string]interface{})
	dataFailureStringInGroup := make(map[string]interface{})

	dataOk["name"] = "test"
	dataOk["email"] = "test@test.com"
	dataOk["preferredUsername"] = "test"
	dataOk["groups"] = []interface{}{"groupA", "groupB"}
	dataOk["avatarURL"] = "http://image.avatar.com"

	dataFailureEmail["name"] = "test"
	dataFailureEmail["email"] = 4
	dataFailureEmail["preferredUsername"] = "test"
	dataFailureEmail["groups"] = []interface{}{"groupA", "groupB"}
	dataFailureEmail["avatarURL"] = "http://image.avatar.com"

	dataFailureGroup["name"] = "test"
	dataFailureGroup["email"] = "test@test.com"
	dataFailureGroup["preferredUsername"] = "test"
	dataFailureGroup["groups"] = "groupA"
	dataFailureGroup["avatarURL"] = "http://image.avatar.com"

	dataFailureStringInGroup["name"] = "test"
	dataFailureStringInGroup["email"] = "test@test.com"
	dataFailureStringInGroup["preferredUsername"] = "test"
	dataFailureStringInGroup["groups"] = []int{123, 456}
	dataFailureStringInGroup["avatarURL"] = "http://image.avatar.com"

	config := userInfo{}
	config, err := updateConfig(config, dataOk)
	if err != nil {
		t.Fatal(err)
	}
	if config.name != "test" || config.email != "test@test.com" || config.preferredUsername != "test" || config.avatarURL != "http://image.avatar.com" || config.groups[0] != "groupA" || config.groups[1] != "groupB" {
		t.Fatal(fmt.Errorf("parsing incorrect, values not matching: %s", config))
	}

	config = userInfo{}
	config, err = updateConfig(config, dataFailureEmail)
	if err == nil {
		t.Fatal(fmt.Errorf("parsing incorrect, email is not string but did not fail"))
	} else {
		log.Logger.Info().Msgf("obtained expected error: %s", err)
	}

	config = userInfo{}
	config, err = updateConfig(config, dataFailureGroup)
	if err == nil {
		t.Fatal(fmt.Errorf("parsing incorrect, group is not array but did not fail"))
	} else {
		log.Logger.Info().Msgf("obtained expected error: %s", err)
	}

	config = userInfo{}
	config, err = updateConfig(config, dataFailureStringInGroup)
	if err == nil {
		t.Fatal(fmt.Errorf("parsing incorrect, group array is not string but did not fail"))
	} else {
		log.Logger.Info().Msgf("obtained expected error: %s", err)
	}

}
