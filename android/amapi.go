// Package android は Google の Android Management API（AMAPI）で Android の端末を管理する。
//
// 組織ごとに Google の enterprise を 1 つ作り、端末ごとに AMAPI のポリシーを 1 つ作る。
// 端末ごとにするのは、端末ごとに違う通信フィルターのホスト名（DoT）を配るため。
package android

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// Scope は AMAPI の OAuth のスコープ。
const Scope = "https://www.googleapis.com/auth/androidmanagement"

// DefaultBaseURL は AMAPI の入り口。
const DefaultBaseURL = "https://androidmanagement.googleapis.com/v1/"

// Client は AMAPI の HTTP のクライアント。使う機能の分だけを持つ。
type Client struct {
	// BaseURL は末尾が "/" の入り口。空なら DefaultBaseURL。
	BaseURL string
	// HTTP は認証済みのクライアント。NewClient で作る。
	HTTP *http.Client
}

// NewClient は Google Cloud のサービスアカウントの鍵（JSON）で認証するクライアントを作る。
func NewClient(ctx context.Context, serviceAccountJSON []byte) (*Client, error) {
	creds, err := google.CredentialsFromJSONWithType(ctx, serviceAccountJSON, google.ServiceAccount, Scope)
	if err != nil {
		return nil, fmt.Errorf("android: サービスアカウントの鍵: %w", err)
	}
	hc := &http.Client{Transport: &oauth2.Transport{Source: creds.TokenSource}, Timeout: 30 * time.Second}
	return &Client{HTTP: hc}, nil
}

// APIError は AMAPI が返したエラー。
type APIError struct {
	Status  int
	Code    string // "NOT_FOUND" など
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("android management api: %d %s: %s", e.Status, e.Code, e.Message)
}

// IsNotFound は対象が無いというエラーか。
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	base := c.BaseURL
	if base == "" {
		base = DefaultBaseURL
	}
	u := base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(b, &e)
		return &APIError{Status: resp.StatusCode, Code: e.Error.Status, Message: e.Error.Message}
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}

// SignupURL は enterprise を作る Google の画面。
type SignupURL struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// CreateSignupURL は enterprise を作る画面の URL を作る。終わると callbackURL に enterpriseToken が付いて戻る。
func (c *Client) CreateSignupURL(ctx context.Context, projectID, callbackURL, adminEmail string) (SignupURL, error) {
	q := url.Values{"projectId": {projectID}, "callbackUrl": {callbackURL}}
	if adminEmail != "" {
		q.Set("adminEmail", adminEmail)
	}
	var out SignupURL
	err := c.do(ctx, http.MethodPost, "signupUrls", q, nil, &out)
	return out, err
}

// Enterprise は AMAPI の enterprise。
type Enterprise struct {
	Name                  string `json:"name,omitempty"`
	EnterpriseDisplayName string `json:"enterpriseDisplayName,omitempty"`
}

// CreateEnterprise は登録の画面から戻ってきた enterpriseToken で enterprise を作る。
func (c *Client) CreateEnterprise(ctx context.Context, projectID, signupURLName, enterpriseToken string, e Enterprise) (Enterprise, error) {
	q := url.Values{"projectId": {projectID}, "signupUrlName": {signupURLName}, "enterpriseToken": {enterpriseToken}}
	var out Enterprise
	err := c.do(ctx, http.MethodPost, "enterprises", q, e, &out)
	return out, err
}

// PatchPolicy はポリシーを作るか更新する。mask が空なら全体を置き換える。
func (c *Client) PatchPolicy(ctx context.Context, name string, policy map[string]any, mask []string) error {
	var q url.Values
	if len(mask) > 0 {
		q = url.Values{"updateMask": {strings.Join(mask, ",")}}
	}
	return c.do(ctx, http.MethodPatch, name, q, policy, nil)
}

// DeletePolicy はポリシーを消す。使っている端末があると消せない。
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, name, nil, nil, nil)
}

// EnrollmentToken は端末の登録に使う一時的な鍵。
type EnrollmentToken struct {
	Name               string `json:"name,omitempty"`
	Value              string `json:"value,omitempty"`
	PolicyName         string `json:"policyName,omitempty"`
	Duration           string `json:"duration,omitempty"` // "3600s"
	ExpirationTime     string `json:"expirationTimestamp,omitempty"`
	AllowPersonalUsage string `json:"allowPersonalUsage,omitempty"`
	OneTimeOnly        bool   `json:"oneTimeOnly,omitempty"`
	AdditionalData     string `json:"additionalData,omitempty"`
	QRCode             string `json:"qrCode,omitempty"`
}

// CreateEnrollmentToken は登録の鍵を作る。
func (c *Client) CreateEnrollmentToken(ctx context.Context, enterprise string, t EnrollmentToken) (EnrollmentToken, error) {
	var out EnrollmentToken
	err := c.do(ctx, http.MethodPost, enterprise+"/enrollmentTokens", nil, t, &out)
	return out, err
}

// Device は AMAPI の端末（使う項目だけ）。
type Device struct {
	Name                string `json:"name"`
	State               string `json:"state"`
	AppliedState        string `json:"appliedState"`
	ManagementMode      string `json:"managementMode"`
	Ownership           string `json:"ownership"`
	PolicyName          string `json:"policyName"`
	PolicyCompliant     bool   `json:"policyCompliant"`
	EnrollmentTime      string `json:"enrollmentTime"`
	LastStatusReport    string `json:"lastStatusReportTime"`
	EnrollmentTokenData string `json:"enrollmentTokenData"`
	HardwareInfo        struct {
		Brand        string `json:"brand"`
		Manufacturer string `json:"manufacturer"`
		Model        string `json:"model"`
	} `json:"hardwareInfo"`
	SoftwareInfo struct {
		AndroidVersion      string `json:"androidVersion"`
		SecurityPatchLevel  string `json:"securityPatchLevel"`
		AndroidBuildNumber  string `json:"androidBuildNumber"`
		PrimaryLanguageCode string `json:"primaryLanguageCode"`
	} `json:"softwareInfo"`
	DeviceSettings struct {
		IsEncrypted    bool `json:"isEncrypted"`
		IsDeviceSecure bool `json:"isDeviceSecure"`
	} `json:"deviceSettings"`
	NonComplianceDetails []struct {
		SettingName         string `json:"settingName"`
		NonComplianceReason string `json:"nonComplianceReason"`
		PackageName         string `json:"packageName"`
	} `json:"nonComplianceDetails"`
}

// ListDevices は enterprise の端末をすべて返す。
func (c *Client) ListDevices(ctx context.Context, enterprise string) ([]Device, error) {
	var all []Device
	token := ""
	for {
		q := url.Values{"pageSize": {"100"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Devices       []Device `json:"devices"`
			NextPageToken string   `json:"nextPageToken"`
		}
		if err := c.do(ctx, http.MethodGet, enterprise+"/devices", q, nil, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Devices...)
		if page.NextPageToken == "" {
			return all, nil
		}
		token = page.NextPageToken
	}
}

// Command は端末への命令。
type Command struct {
	Type     string `json:"type"`               // "LOCK"・"REBOOT" など
	Duration string `json:"duration,omitempty"` // 命令の有効期限
}

// IssueCommand は端末に命令を送る。
func (c *Client) IssueCommand(ctx context.Context, device string, cmd Command) error {
	return c.do(ctx, http.MethodPost, device+":issueCommand", nil, cmd, nil)
}

// DeleteDevice は端末を enterprise から外す。完全管理の端末は初期化され、私物は仕事用プロファイルが消える。
func (c *Client) DeleteDevice(ctx context.Context, device, reason string) error {
	var q url.Values
	if reason != "" {
		q = url.Values{"wipeReasonMessage": {reason}}
	}
	return c.do(ctx, http.MethodDelete, device, q, nil, nil)
}
