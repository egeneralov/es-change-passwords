package request

import (
	"bytes"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/egeneralov/es-change-passwords/internal/types"
)

// Do a http.POST request with auth from user object, tls configuration and json payload
func POST(log *zap.Logger, to string, user types.User, tlsConfig *tls.Config, body []byte) (*http.Response, error) {
	log.Info("request.POST", zap.String("url", to), zap.String("user", user.Username))
	var (
		netClient = &http.Client{
			Timeout: time.Second * 10,
			Transport: &http.Transport{
				Dial: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).Dial,
				TLSHandshakeTimeout: 5 * time.Second,
				TLSClientConfig:     tlsConfig,
			},
		}
		response *http.Response
		request  *http.Request
		err      error
	)

	request, err = http.NewRequest(http.MethodPost, to, bytes.NewBuffer(body))
	if err != nil {
		return response, err
	}

	if user.Username != "" && user.Password != "" {
		request.Header.Set("Authorization", "Basic "+basicAuth(user.Username, user.Password))
	} else {
		log.Warn("username or password are empty, skipping Authorization header", zap.String("username", user.Username))
	}

	request.Header.Set("Content-type", "application/json")

	response, err = netClient.Do(request)
	if err != nil {
		log.Error("request failed", zap.String("error", err.Error()))
		return response, err
	}

	//if response.StatusCode == http.StatusUnauthorized {
	//	return nil, fmt.Errorf("http.StatusUnauthorized for user %+v", user.Username)
	//}
	//if response.StatusCode == http.StatusForbidden {
	//	return nil, fmt.Errorf("http.StatusForbidden for user %+v", user.Username)
	//}

	return response, nil
}
