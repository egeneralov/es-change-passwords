package es

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"go.uber.org/zap"

	"github.com/egeneralov/es-change-passwords/internal/answer"
	"github.com/egeneralov/es-change-passwords/internal/request"
	"github.com/egeneralov/es-change-passwords/internal/types"
)

func GetRoot(log *zap.Logger, url string, user types.User, tlsConfig *tls.Config) (r answer.Root, err error) {
	log.Info("GetRoot")
	var (
		body     []byte
		response *http.Response
	)

	response, err = request.GET(
		log,
		url,
		user,
		tlsConfig,
	)
	if err != nil {
		return
	}

	body, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &r)
	if err != nil {
		return
	}

	//if r.Tagline != "You Know, for Search" {
	//	err = fmt.Errorf(
	//		"error making request: %+v",
	//		string(body),
	//	)
	//}

	return
}
