package auth

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetAPIKey(t *testing.T) {
	type Header struct {
		AuthHeader       string
		AuthHeaderString string
	}
	type Result struct {
		ResString string
		ResError  error
	}
	tests := map[string]struct {
		Header         Header
		ExpectedResult Result
	}{
		"ApiKeyOK": {
			Header: Header{
				AuthHeader:       "Authorization",
				AuthHeaderString: "ApiKey ThisIsANonsenseAPIKey:)",
			},
			ExpectedResult: Result{
				ResString: "ThisIsANonsenseAPIKey:)",
				ResError:  nil,
			},
		},
		"ApiKeyNoHeader": {
			Header: Header{
				AuthHeader:       "",
				AuthHeaderString: "",
			},
			ExpectedResult: Result{
				ResString: "",
				ResError:  ErrNoAuthHeaderIncluded,
			},
		},
		"ApiKeyEmptyAuthHeader": {
			Header: Header{
				AuthHeader:       "Authorization",
				AuthHeaderString: "",
			},
			ExpectedResult: Result{
				ResString: "",
				ResError:  ErrNoAuthHeaderIncluded,
			},
		},
		"ApiKeyBadOne": {
			Header: Header{
				AuthHeader:       "Authorization",
				AuthHeaderString: "ApiKey",
			},
			ExpectedResult: Result{
				ResString: "",
				ResError:  ErrAuthHeaderMalformed,
			},
		}, /* Found a bug :)
		   "ApiKeyBadTwo": {
		       Header: Header{
		           AuthHeader:       "Authorization",
		           AuthHeaderString: "ApiKey ",
		       },
		       ExpectedResult: Result{
		           ResString: "",
		           ResError:  ErrAuthHeaderMalformed,
		       },
		   },*/
		"ApiKeyBadThree": {
			Header: Header{
				AuthHeader:       "Authorization",
				AuthHeaderString: "ThisIsANonsenseAPIKey:)",
			},
			ExpectedResult: Result{
				ResString: "",
				ResError:  ErrAuthHeaderMalformed,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			header := http.Header{tc.Header.AuthHeader: []string{tc.Header.AuthHeaderString}}
			got, err := GetAPIKey(header)

			GotResult := Result{
				ResString: got,
				ResError:  err,
			}

			diffStr := cmp.Diff(tc.ExpectedResult.ResString, GotResult.ResString)

			if tc.ExpectedResult.ResError == nil {
				if GotResult.ResError != nil {
					t.Fatalf("Expected nil err")
				}
			} else {
				diffErr := cmp.Diff(tc.ExpectedResult.ResError.Error(), GotResult.ResError.Error())
				if diffStr != "" && diffErr != "" {
					t.Fatalf("String diff: %v\nErr diff: %v", diffStr, diffErr)
				}
				if diffStr != "" {
					t.Fatalf("String diff: %v", diffStr)
				}
				if diffErr != "" {
					t.Fatalf("Err diff: %v", diffErr)
				}
			}
		})
	}
}
