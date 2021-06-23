package main

import (
	"regexp"

	mapset "github.com/deckarep/golang-set"
	"github.com/kubewarden/gjson"
	kubewarden "github.com/kubewarden/policy-sdk-go"

	"fmt"
)

type Settings struct {
	DeniedLabels      mapset.Set                    `json:"denied_labels"`
	ConstrainedLabels map[string]*RegularExpression `json:"constrained_labels"`
}

type RegularExpression struct {
	*regexp.Regexp
}

func CompileRegularExpression(expr string) (*RegularExpression, error) {
	nativeRegExp, err := regexp.Compile(expr)
	if err != nil {
		return nil, err
	}
	return &RegularExpression{nativeRegExp}, nil
}

func (r *RegularExpression) UnmarchalText(text []byte) error {
	nativeRegExp, err := regexp.Compile(string(text))
	if err != nil {
		return err
	}
	r.Regexp = nativeRegExp
	return nil
}

func (r *RegularExpression) MarshalText() ([]byte, error) {
	if r.Regexp != nil {
		return []byte(r.Regexp.String()), nil
	}
	return nil, nil
}

func NewSettingsFromValidationReq(payload []byte) (Settings, error) {
	return newSettings(
		payload,
		"settings.denied_labels",
		"settings.constrained_labels")
}

func NewSettingsFromValidateSettingsPayload(payload []byte) (Settings, error) {
	if !gjson.ValidBytes(payload) {
		return Settings{}, fmt.Errorf("denied JSON payload")
	}
	return newSettings(
		payload,
		"denied_labels",
		"constrained_labels")
}

func newSettings(payload []byte, paths ...string) (Settings, error) {
	if len(paths) != 2 {
		return Settings{}, fmt.Errorf("wrong number of json paths")
	}

	data := gjson.GetManyBytes(payload, paths...)

	deniedLabels := mapset.NewThreadUnsafeSet()
	data[0].ForEach(func(_, entry gjson.Result) bool {
		deniedLabels.Add(entry.String())
		return true
	})

	constrainedLabels := make(map[string]*RegularExpression)
	var err error
	data[1].ForEach(func(key, value gjson.Result) bool {
		var regExp *RegularExpression
		regExp, err = CompileRegularExpression(value.String())
		if err != nil {
			return false
		}

		constrainedLabels[key.String()] = regExp
		return true
	})
	if err != nil {
		return Settings{}, err
	}

	return Settings{
		DeniedLabels:      deniedLabels,
		ConstrainedLabels: constrainedLabels,
	}, nil
}

func (s *Settings) Valid() (bool, error) {
	constrainedLabels := mapset.NewThreadUnsafeSet()

	for label := range s.ConstrainedLabels {
		constrainedLabels.Add(label)
	}

	constrainedAndDenied := constrainedLabels.Intersect(s.DeniedLabels)
	if constrainedAndDenied.Cardinality() != 0 {
		return false,
			fmt.Errorf("These labels cannot be constrained and denied at the same time: %v", constrainedAndDenied)
	}

	return true, nil
}

func validateSettings(payload []byte) ([]byte, error) {
	settings, err := NewSettingsFromValidateSettingsPayload(payload)
	if err != nil {
		// this happens when one of the user-defined regular expressions are invalid
		return kubewarden.RejectSettings(
			kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
	}

	valid, err := settings.Valid()
	if valid {
		return kubewarden.AcceptSettings()
	}
	return kubewarden.RejectSettings(
		kubewarden.Message(fmt.Sprintf("Provided settings are not valid: %v", err)))
}
