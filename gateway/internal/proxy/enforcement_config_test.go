package proxy

import (
	"reflect"
	"testing"

	"github.com/Adnan-Safdari/Intelligent_API_Security_Gateway/internal/config"
)

// A new section on EnforcementConfig has to be carried in three places before
// it does anything: main.go builds the server Config, Config.Enforcement()
// reassembles the block for the settings watcher, and the settings package
// puts it on the wire. Forgetting the middle one is silent -- the detector is
// constructed, reads a zero config, switches itself off, and the only symptom
// is a startup line that never appears.
//
// This walks EnforcementConfig by reflection rather than naming its sections,
// so a section added later fails here instead of being quietly dropped.
func TestEnforcementCarriesEverySection(t *testing.T) {
	var enforcement config.EnforcementConfig
	sections := reflect.TypeOf(enforcement)

	server := reflect.New(reflect.TypeOf(Config{})).Elem()

	for i := 0; i < sections.NumField(); i++ {
		name := sections.Field(i).Name

		target := server.FieldByName(name)
		if !target.IsValid() {
			t.Fatalf("Config has no %s field, so main.go cannot supply it", name)
		}
		enabled := target.FieldByName("Enabled")
		if name == "AdaptiveRateLimit" {
			target.FieldByName("Burst").SetInt(7)
			continue
		}
		if !enabled.IsValid() || enabled.Kind() != reflect.Bool {
			t.Fatalf("%s has no Enabled flag; this test needs updating for it", name)
		}
		enabled.SetBool(true)
	}

	got := server.Interface().(Config).Enforcement()

	for i := 0; i < sections.NumField(); i++ {
		name := sections.Field(i).Name
		if name == "AdaptiveRateLimit" {
			if got.AdaptiveRateLimit.Burst != 7 {
				t.Error("Config.Enforcement() drops adaptive quota settings")
			}
			continue
		}
		if !reflect.ValueOf(got).FieldByName(name).FieldByName("Enabled").Bool() {
			t.Errorf("Config.Enforcement() drops %s -- it would boot switched off", name)
		}
	}
}
