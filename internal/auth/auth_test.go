package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	apiKey := "some-random-api-key"

	tests := map[string]struct {
		setupHeader func() http.Header
		want        string
		wantErr     error
	}{
		"Non-malformed Auth Header": {
			setupHeader: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey "+apiKey)
				return h
			},
			want:    apiKey,
			wantErr: nil,
		},

		"Malformed Auth Header: No 'ApiKey ...'": {
			setupHeader: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", " "+apiKey)
				return h
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},

		"Empty ApiKey": {
			setupHeader: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey")
				return h
			},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},

		"No Auth Header": {
			setupHeader: func() http.Header {
				return make(http.Header)
			},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.setupHeader())
			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error: %v, got nil", tc.wantErr)
					return
				}

				if err.Error() != tc.wantErr.Error() {
					t.Fatalf("expected error: %v, got: %v", tc.wantErr, err)
					return
				}
			} else if err != nil {
				t.Fatalf("expected no error, got: %v", err)
				return
			}

			if got != tc.want {
				t.Fatalf("%s: expected: %v, got: %v", name, tc.want, got)
			}
		})

	}
}
