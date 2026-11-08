package rulescli

import "testing"

func TestCheckBaseURL(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://mdm.example:8093": true, "http://127.0.0.1:8093": true, "http://localhost:8093": true, "http://[::1]:8093": true,
		"http://mdm.example:8093": false, "ftp://mdm.example": false, "https://u:p@mdm.example": false, "": false, "mdm.example": false,
	} {
		if err := checkBaseURL(raw); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
}
