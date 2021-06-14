package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"

	"github.com/egeneralov/es-change-passwords/internal/answer"
	"github.com/egeneralov/es-change-passwords/internal/es"
	"github.com/egeneralov/es-change-passwords/internal/request"
	"github.com/egeneralov/es-change-passwords/internal/types"
)

var (
	Configuration types.Configuration
	tlsConfig     *tls.Config

	log *zap.Logger

	cfgFile  = flag.String("config", "config.yml", "Configuration file.")
	endpoint = flag.String("endpoint", "https://127.0.0.1:9200", "Elastic http port")
	certFile = flag.String("tls-cert", "", "A PEM encoded certificate file.")
	keyFile  = flag.String("tls-key", "", "A PEM encoded private key file.")
	caFile   = flag.String("tls-ca", "", "A PEM encoded CA's certificate file.")
	insecure = flag.Bool("insecure", false, "TLS: InsecureSkipVerify")
)

func main() {
	var (
		err     error
		elastic types.User
	)

	log, err = zap.NewProduction()
	if err != nil {
		panic(err)
	}

	log.Info("application started")

	Configuration, err = parseConfiguration(log)
	if err != nil {
		//panic(err)
		log.Fatal("failed to parseConfiguration", zap.String("error", err.Error()))
		return
	}

	tlsConfig, err = prepareTLS(log, *certFile, *keyFile, *caFile, *insecure)
	if err != nil {
		//panic(err)
		log.Fatal("failed to prepareTLS", zap.String("error", err.Error()))
		return
	}

	elastic = Configuration.GetElasticUser(log)

	err = enshureElasticUser(log, elastic, *endpoint, tlsConfig)
	if err != nil {
		//panic(err)
		log.Fatal("failed to enshureElasticUser", zap.String("error", err.Error()))
		return
	}

	for _, u := range Configuration.Passwords {
		if u.Username == elastic.Username {
			continue
		}
		log.Info("Processing user", zap.String("username", u.Username))
		var (
			isPasswordVaild bool
			err             error
		)

		isPasswordVaild, err = checkAuth(log, *endpoint, u, tlsConfig)
		if err != nil {
			//panic(err)
			log.Fatal("checkAuth failed", zap.String("error", err.Error()))
			return
		}
		if isPasswordVaild {
			log.Info("password already valid, skipping changePassword invocation")
			continue
		}

		err = changePassword(log, u, elastic, *endpoint, tlsConfig)
		if err != nil {
			//panic(err)
			log.Fatal("failed to changePassword", zap.String("error", err.Error()))
			return
		}
	}
	log.Info("application finished")
}

// Enshure elastic user u.Password valid OR change it's password via u.OldPassword OR die
func enshureElasticUser(log *zap.Logger, u types.User, endpoint string, tlsConfig *tls.Config) (err error) {
	log.Info("enshureElasticUser")
	var (
		isPasswordVaild    bool
		isOldPasswordVaild bool
	)

	isPasswordVaild, err = checkAuth(log, endpoint, u, tlsConfig)
	if err != nil {
		return
	}
	if isPasswordVaild {
		return
	}

	isOldPasswordVaild, err = checkAuth(log, endpoint, types.User{
		Username: u.Username,
		Password: u.OldPassword,
	}, tlsConfig)

	if err != nil {
		return
	}
	if !isOldPasswordVaild {
		return fmt.Errorf("can't change elastic user password, because .OldPassword is invalid")
	}

	err = changePassword(
		log,
		// target
		types.User{
			Username: u.Username,
			Password: u.Password,
		},
		// via
		types.User{
			Username: u.Username,
			Password: u.OldPassword,
		},
		endpoint,
		tlsConfig,
	)

	return
}

// Check is user.Password have a valid auth
func checkAuth(log *zap.Logger, endpoint string, user types.User, tlsConfig *tls.Config) (bool, error) {
	log.Info("checkAuth")
	var (
		result bool
		err    error
		r      answer.Root
	)

	r, err = es.GetRoot(log, endpoint, user, tlsConfig)
	if err != nil {
		return result, err
	}

	if r.Name == "" || r.ClusterName == "" || r.ClusterUUID == "" || r.Tagline == "" || r.Version.Number == "" || r.Version.LuceneVersion == "" {
		result = false
	} else {
		result = true
	}

	return result, err
}

// Prepare tls context
func prepareTLS(log *zap.Logger, certFile, keyFile, caFile string, insecure bool) (tlsConfig *tls.Config, err error) {
	log.Info("prepareTLS")
	var (
		caCertPool = x509.NewCertPool()
		cert       tls.Certificate
		caCert     []byte
		ok bool
	)
	if certFile != "" && keyFile != "" {
		log.Info("Loading client cert")
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return
		}
	}

	if caFile != "" {
		log.Info("Loading CA cert")
		caCert, err = ioutil.ReadFile(caFile)
		if err != nil {
			return
		}
		ok = caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, fmt.Errorf("failed to AppendCertsFromPEM(caCert)")
		}
	}

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
		InsecureSkipVerify: insecure,
	}
	//tlsConfig.BuildNameToCertificate()
	return
}

// Prepare configuration
func parseConfiguration(log *zap.Logger) (types.Configuration, error) {
	log.Info("parseConfiguration")
	var (
		raw           []byte
		configuration = types.Configuration{}
		err           error
	)
	// flags
	flag.Parse()
	// read file
	log.Info("reading configuration file", zap.String("path", *cfgFile))
	raw, err = ioutil.ReadFile(*cfgFile)
	if err != nil {
		return types.Configuration{}, err
	}
	// yaml parse
	log.Info("parsing yaml")
	err = yaml.Unmarshal(raw, &configuration)
	if err != nil {
		return types.Configuration{}, err
	}
	return configuration, nil
}

// Change password for target user via elastic user (auth)
func changePassword(log *zap.Logger, target, elastic types.User, endpoint string, tlsConfig *tls.Config) (err error) {
	var (
		url      = fmt.Sprintf("%v/_security/user/%v/_password", endpoint, target.Username)
		payload  = fmt.Sprintf("{\"password\": \"%v\"}", target.Password)
		response *http.Response

		esAnswer []byte
	)

	response, err = request.POST(log, url, elastic, tlsConfig, []byte(payload))
	if err != nil {
		return
	}

	if response.StatusCode != http.StatusOK {
		log.Error("response.StatusCode != http.StatusOK, reading body")
		esAnswer, err = ioutil.ReadAll(response.Body)
		if err != nil {
			return
		}
		err = fmt.Errorf("failed to change password for user %v: %+v", target.Username, string(esAnswer))
	}

	return
}
