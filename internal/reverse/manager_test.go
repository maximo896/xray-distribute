package reverse

import "testing"

func TestEnforceSqldetRetryConfig(t *testing.T) {
	config := map[string]interface{}{
		"http": map[string]interface{}{
			"fail_retries": 0,
			"proxy":        "http://127.0.0.1:8080",
		},
		"plugins": map[string]interface{}{
			"sqldet": map[string]interface{}{
				"enabled":                 true,
				"time_based_detection":    true,
				"boolean_based_detection": true,
			},
		},
	}

	enforceSqldetRetryConfig(config)

	httpCfg := config["http"].(map[string]interface{})
	if got := httpCfg["fail_retries"]; got != sqldetFailRetries {
		t.Fatalf("expected fail_retries=%d, got %#v", sqldetFailRetries, got)
	}
	if got := httpCfg["proxy"]; got != "http://127.0.0.1:8080" {
		t.Fatalf("expected existing http config to be preserved, got %#v", got)
	}

	sqldet := config["plugins"].(map[string]interface{})["sqldet"].(map[string]interface{})
	if got := sqldet["enabled"]; got != true {
		t.Fatalf("expected sqldet to remain enabled, got %#v", got)
	}
	if got := sqldet["time_based_detection"]; got != true {
		t.Fatalf("expected sqldet options to be preserved, got %#v", got)
	}
}

func TestEnforceSqldetRetryConfigCreatesMissingSections(t *testing.T) {
	config := map[string]interface{}{}

	enforceSqldetRetryConfig(config)

	httpCfg := config["http"].(map[string]interface{})
	if got := httpCfg["fail_retries"]; got != sqldetFailRetries {
		t.Fatalf("expected fail_retries=%d, got %#v", sqldetFailRetries, got)
	}

	sqldet := config["plugins"].(map[string]interface{})["sqldet"].(map[string]interface{})
	if got := sqldet["enabled"]; got != true {
		t.Fatalf("expected sqldet enabled default, got %#v", got)
	}
}
