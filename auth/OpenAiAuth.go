package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"

	arkose "github.com/yhhit/funcaptcha"
)

type Error struct {
	Location   string
	StatusCode int
	Details    string
}

func NewError(location string, statusCode int, details string) *Error {
	return &Error{
		Location:   location,
		StatusCode: statusCode,
		Details:    details,
	}
}

type AccountCookies map[string][]*http.Cookie

var allCookies AccountCookies

type Result struct {
	AccessToken  string `json:"access_token"`
	PUID         string `json:"puid"`
	SessionToken string `json:"session_token"`
	TeamUserID   string `json:"team_uid,omitempty"`
}

const (
	defaultErrorMessageKey             = "errorMessage"
	AuthorizationHeader                = "Authorization"
	XAuthorizationHeader               = "X-Authorization"
	ContentType                        = "application/x-www-form-urlencoded"
	UserAgent                          = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
	Auth0Url                           = "https://auth0.openai.com"
	LoginPasswordUrl                   = Auth0Url + "/u/login/password?state="
	ParseUserInfoErrorMessage          = "Failed to parse user login info."
	GetAuthorizedUrlErrorMessage       = "Failed to get authorized url."
	GetStateErrorMessage               = "Failed to get state."
	EmailInvalidErrorMessage           = "Email is not valid."
	EmailOrPasswordInvalidErrorMessage = "Email or password is not correct."
	GetAccessTokenErrorMessage         = "Failed to get access token."
	GetArkoseTokenErrorMessage         = "Failed to get arkose token."
	defaultTimeoutSeconds              = 600 // 10 minutes

	csrfUrl                  = "https://chatgpt.com/api/auth/csrf"
	promptLoginUrl           = "https://chatgpt.com/api/auth/signin/login-web?prompt=login&screen_hint=login"
	getCsrfTokenErrorMessage = "Failed to get CSRF token."
	authSessionUrl           = "https://chatgpt.com/api/auth/session"
)

var u, _ = url.Parse("https://chatgpt.com")

type UserLogin struct {
	Username string
	Password string
	client   tls_client.HttpClient
	Result   Result
}

//goland:noinspection GoUnhandledErrorResult,SpellCheckingInspection
func NewHttpClient(proxyUrl string) tls_client.HttpClient {
	client := getHttpClient()

	if proxyUrl != "" {
		client.SetProxy(proxyUrl)
	}

	return client
}

func getHttpClient() tls_client.HttpClient {
	client, _ := tls_client.NewHttpClient(tls_client.NewNoopLogger(), []tls_client.HttpClientOption{
		tls_client.WithCookieJar(tls_client.NewCookieJar()),
		tls_client.WithTimeoutSeconds(600),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
	}...)
	return client
}

func NewAuthenticator(emailAddress, password, proxy string) *UserLogin {
	userLogin := &UserLogin{
		Username: emailAddress,
		Password: password,
		client:   NewHttpClient(proxy),
	}
	return userLogin
}

func NewAuthenticatorWithResult(emailAddress, password, proxy string, result Result) *UserLogin {
	userLogin := &UserLogin{
		Username: emailAddress,
		Password: password,
		client:   NewHttpClient(proxy),
		Result:   result,
	}
	return userLogin
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) GetAuthorizedUrl(csrfToken string) (string, int, error) {
	form := url.Values{
		"callbackUrl": {"/"},
		"csrfToken":   {csrfToken},
		"json":        {"true"},
	}
	req, err := http.NewRequest(http.MethodPost, promptLoginUrl, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode, errors.New(GetAuthorizedUrlErrorMessage)
	}

	responseMap := make(map[string]string)
	json.NewDecoder(resp.Body).Decode(&responseMap)
	return responseMap["url"], http.StatusOK, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) GetState(authorizedUrl string) (int, error) {
	req, err := http.NewRequest(http.MethodGet, authorizedUrl, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, errors.New(GetStateErrorMessage)
	}
	return http.StatusOK, nil
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) CheckUsername(authorizedUrl string, username string) (string, string, int, error) {
	u, _ := url.Parse(authorizedUrl)
	query := u.Query()
	query.Del("prompt")
	query.Set("login_hint", username)
	req, _ := http.NewRequest(http.MethodGet, Auth0Url+"/authorize?"+query.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Referer", "https://auth.openai.com/")
	userLogin.client.SetFollowRedirect(false)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		redir := resp.Header.Get("Location")
		req, _ := http.NewRequest(http.MethodGet, Auth0Url+redir, nil)
		req.Header.Set("User-Agent", UserAgent)
		req.Header.Set("Referer", "https://auth.openai.com/")
		resp, err := userLogin.client.Do(req)
		if err != nil {
			return "", "", http.StatusInternalServerError, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", "", http.StatusInternalServerError, err
		}
		var dx string
		re := regexp.MustCompile(`blob: "([^"]+?)"`)
		matches := re.FindStringSubmatch(string(body))
		if len(matches) > 1 {
			dx = matches[1]
		}
		u, _ := url.Parse(redir)
		state := u.Query().Get("state")
		return state, dx, http.StatusOK, nil
	} else {
		return "", "", http.StatusInternalServerError, err
	}
}

func (userLogin *UserLogin) setArkose(dx string) (int, error) {
	token, err := arkose.GetOpenAIAuthToken("", dx, userLogin.client.GetProxy())
	if err == nil {
		u, _ := url.Parse("https://openai.com")
		cookies := []*http.Cookie{}
		userLogin.client.GetCookieJar().SetCookies(u, append(cookies, &http.Cookie{Name: "arkoseToken", Value: token}))
		return http.StatusOK, nil
	} else {
		println("Error getting auth Arkose token")
		return http.StatusInternalServerError, err
	}
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat
func (userLogin *UserLogin) CheckPassword(state string, username string, password string) (string, int, error) {
	formParams := url.Values{
		"state":    {state},
		"username": {username},
		"password": {password},
	}
	req, err := http.NewRequest(http.MethodPost, LoginPasswordUrl+state, strings.NewReader(formParams.Encode()))
	req.Header.Set("Content-Type", ContentType)
	req.Header.Set("User-Agent", UserAgent)
	userLogin.client.SetFollowRedirect(false)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode == http.StatusBadRequest {
		return "", resp.StatusCode, errors.New(EmailOrPasswordInvalidErrorMessage)
	}

	if resp.StatusCode == http.StatusFound {
		req, _ := http.NewRequest(http.MethodGet, Auth0Url+resp.Header.Get("Location"), nil)
		req.Header.Set("User-Agent", UserAgent)
		resp, err := userLogin.client.Do(req)
		if err != nil {
			return "", http.StatusInternalServerError, err
		}

		defer resp.Body.Close()
		if resp.StatusCode == http.StatusFound {
			location := resp.Header.Get("Location")
			if strings.HasPrefix(location, "/u/mfa-otp-challenge") {
				return "", http.StatusBadRequest, errors.New("Login with two-factor authentication enabled is not supported currently.")
			}

			req, _ := http.NewRequest(http.MethodGet, location, nil)
			req.Header.Set("User-Agent", UserAgent)
			resp, err := userLogin.client.Do(req)
			if err != nil {
				return "", http.StatusInternalServerError, err
			}

			defer resp.Body.Close()
			if resp.StatusCode == http.StatusFound {
				return "", http.StatusOK, nil
			}

			if resp.StatusCode == http.StatusTemporaryRedirect {
				errorDescription := req.URL.Query().Get("error_description")
				if errorDescription != "" {
					return "", resp.StatusCode, errors.New(errorDescription)
				}
			}

			return "", resp.StatusCode, errors.New(GetAccessTokenErrorMessage)
		}

		return "", resp.StatusCode, errors.New(EmailOrPasswordInvalidErrorMessage)
	}

	return "", resp.StatusCode, nil
}

func extractCookieValue(req *http.Request) (string, bool) {
	// 获取请求中的所有 Cookies
	cookies := req.Cookies()

	// 遍历 Cookies 查找特定的 Cookie
	for _, cookie := range cookies {
		if cookie.Name == "__Secure-next-auth.session-token" {
			// 返回找到的 Cookie 的值和 true 表示找到了
			return cookie.Value, true
		}
	}

	// 如果没有找到，返回空字符串和 false
	return "", false
}

//goland:noinspection GoUnhandledErrorResult,GoErrorStringFormat,GoUnusedParameter
func (userLogin *UserLogin) GetAccessTokenInternal(code string) (string, string, int, error) {
	req, err := http.NewRequest(http.MethodGet, authSessionUrl, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", "", http.StatusInternalServerError, err
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests {
			responseMap := make(map[string]string)
			json.NewDecoder(resp.Body).Decode(&responseMap)
			return "", "", resp.StatusCode, errors.New(responseMap["detail"])
		}

		return "", "", resp.StatusCode, errors.New(GetAccessTokenErrorMessage)
	}
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", 0, err
	}
	// Check if access token in data
	if _, ok := result["accessToken"]; !ok {
		result_string := fmt.Sprintf("%v", result)
		return result_string, "", 0, errors.New("missing access token")
	}
	SessionToken, _ := extractCookieValue(req)

	return result["accessToken"].(string), SessionToken, http.StatusOK, nil
}

func (userLogin *UserLogin) Begin() *Error {
	_, err, accessToken, SessionToken := userLogin.GetToken()
	if err != "" {
		return NewError("begin", 0, err)
	}
	userLogin.Result.AccessToken = accessToken
	userLogin.Result.SessionToken = SessionToken
	return nil
}

func (userLogin *UserLogin) GetToken() (int, string, string, string) {
	// get csrf token
	req, _ := http.NewRequest(http.MethodGet, csrfUrl, nil)
	req.Header.Set("User-Agent", UserAgent)
	resp, err := userLogin.client.Do(req)
	if err != nil {
		return http.StatusInternalServerError, err.Error(), "", ""
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, getCsrfTokenErrorMessage, "", ""
	}

	// get authorized url
	responseMap := make(map[string]string)
	json.NewDecoder(resp.Body).Decode(&responseMap)
	authorizedUrl, statusCode, err := userLogin.GetAuthorizedUrl(responseMap["csrfToken"])
	if err != nil {
		return statusCode, err.Error(), "", ""
	}

	// get state
	statusCode, err = userLogin.GetState(authorizedUrl)
	if err != nil {
		return statusCode, err.Error(), "", ""
	}

	// check username
	state, dx, statusCode, err := userLogin.CheckUsername(authorizedUrl, userLogin.Username)
	if err != nil {
		return statusCode, err.Error(), "", ""
	}

	// set arkose captcha
	statusCode, err = userLogin.setArkose(dx)
	if err != nil {
		return statusCode, err.Error(), "", ""
	}

	// check password
	_, statusCode, err = userLogin.CheckPassword(state, userLogin.Username, userLogin.Password)
	if err != nil {
		return statusCode, err.Error(), "", ""
	}

	// get access token
	accessToken, SessionToken, statusCode, err := userLogin.GetAccessTokenInternal("")
	if err != nil {
		return statusCode, err.Error(), "", ""
	}

	return http.StatusOK, "", accessToken, SessionToken
}

func (userLogin *UserLogin) GetAccessToken() string {
	return userLogin.Result.AccessToken
}

func (userLogin *UserLogin) GetSessionToken() string {
	return userLogin.Result.SessionToken
}

func (userLogin *UserLogin) GetPUID() (string, *Error) {
	// Check if user has access token
	if userLogin.Result.AccessToken == "" {
		return "", NewError("get_puid", 0, "Missing access token")
	}
	// Make request to https://chatgpt.com/backend-api/models
	req, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/models?history_and_training_disabled=false", nil)
	// Add headers
	req.Header.Add("Authorization", "Bearer "+userLogin.Result.AccessToken)
	req.Header.Add("User-Agent", UserAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", NewError("get_puid", 0, "Failed to make request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("get_puid", resp.StatusCode, "Failed to make request")
	}
	// Find `_puid` cookie in response
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "_puid" {
			userLogin.Result.PUID = cookie.Value
			return cookie.Value, nil
		}
	}
	// If cookie not found, return error
	return "", NewError("get_puid", 0, "PUID cookie not found")
}

type AccountInfo struct {
	Account struct {
		AccountId   string `json:"account_id"`
		PlanType    string `json:"plan_type"`
		Deactivated bool   `json:"is_deactivated"`
	} `json:"account"`
}
type UserID struct {
	Accounts map[string]AccountInfo `json:"accounts"`
}

func (userLogin *UserLogin) GetTeamUserID() (string, *Error) {
	// Check if user has access token
	if userLogin.Result.AccessToken == "" {
		return "", NewError("get_teamuserid", 0, "Missing access token")
	}
	req, _ := http.NewRequest("GET", "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27", nil)
	// Add headers
	req.Header.Add("Authorization", "Bearer "+userLogin.Result.AccessToken)
	req.Header.Add("User-Agent", UserAgent)

	resp, err := userLogin.client.Do(req)
	if err != nil {
		return "", NewError("get_teamuserid", 0, "Failed to make request")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", NewError("get_teamuserid", resp.StatusCode, "Failed to make request")
	}
	var userId UserID
	err = json.NewDecoder(resp.Body).Decode(&userId)
	if err != nil {
		return "", NewError("get_teamuserid", 0, "teamuserid not found")
	}
	for _, item := range userId.Accounts {
		if item.Account.PlanType == "team" && !item.Account.Deactivated {
			userLogin.Result.TeamUserID = item.Account.AccountId
			return item.Account.AccountId, nil
		}
	}
	// If cookie not found, return error
	return "", NewError("get_teamuserid", 0, "teamuserid not found")
}

func init() {
	allCookies = AccountCookies{}
	file, err := os.Open("cookies.json")
	if err != nil {
		return
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&allCookies)
	if err != nil {
		return
	}
}

func (userLogin *UserLogin) ResetCookies() {
	newCookies := tls_client.NewCookieJar()
	newCookies.SetCookies(u, []*http.Cookie{{
		Name:  "oai-dm-tgt-c-240329",
		Value: "2024-04-02",
	}})
	userLogin.client.SetCookieJar(newCookies)
}

func (userLogin *UserLogin) SaveCookies() *Error {
	cookies := userLogin.client.GetCookieJar().Cookies(u)
	file, err := os.OpenFile("cookies.json", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return NewError("saveCookie", 0, err.Error())
	}
	defer file.Close()
	filtered := []*http.Cookie{}
	expireTime := time.Now().AddDate(0, 0, 7)
	for _, cookie := range cookies {
		if cookie.Expires.After(expireTime) {
			filtered = append(filtered, cookie)
		}
	}
	allCookies[userLogin.Username] = filtered
	encoder := json.NewEncoder(file)
	err = encoder.Encode(allCookies)
	if err != nil {
		return NewError("saveCookie", 0, err.Error())
	}
	return nil
}

func (userLogin *UserLogin) RenewWithCookies() *Error {
	cookies := allCookies[userLogin.Username]
	if len(cookies) == 0 {
		return NewError("readCookie", 0, "no cookies")
	}
	cookies = append(cookies, &http.Cookie{
		Name:  "oai-dm-tgt-c-240329",
		Value: "2024-04-02",
	})
	userLogin.client.GetCookieJar().SetCookies(u, cookies)
	accessToken, SessionToken, statusCode, err := userLogin.GetAccessTokenInternal("")
	if err != nil {
		return NewError("renewToken", statusCode, err.Error())
	}
	userLogin.Result.AccessToken = accessToken
	userLogin.Result.SessionToken = SessionToken
	return nil
}

func (userLogin *UserLogin) GetAuthResult() Result {
	return userLogin.Result
}
