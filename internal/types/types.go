package types

import (
	"os"

	"go.uber.org/zap"
)

type User struct {
	Username    string `yaml:"username"`
	Password    string `yaml:"password"`
	OldPassword string `yaml:"old_password"`
}

type Configuration struct {
	Passwords []User
	/*
		#xpack:
		#  security:
		#    transport:
		#      ssl:
		#        verification_mode: certificate
		#        certificate: test/tls.crt
		#        key: test/tls.key
		#        certificate_authorities:
		#          - "test/ca.crt"


			Xpack struct {
			Security struct {
				Enabled   bool `yaml:"enabled"`
				Transport struct {
					Ssl struct {
						Enabled                bool     `yaml:"enabled"`
						VerificationMode       string   `yaml:"verification_mode"`
						Key                    string   `yaml:"key"`
						Certificate            string   `yaml:"certificate"`
						CertificateAuthorities []string `yaml:"certificate_authorities"`
					} `yaml:"ssl"`
				} `yaml:"transport"`
			} `yaml:"security"`
		} `yaml:"xpack"`
	*/
}

func (c *Configuration) GetElasticUser(log *zap.Logger) User {
	log.Info("GetElasticUser")
	for _, u := range c.Passwords {
		if u.Username == "elastic" {
			log.Info("founded")
			return u
		}
	}
	log.Info("not founded, using os.Getenv")
	return User{
		Username:    "elastic",
		Password:    os.Getenv("ELASTIC_PASSWORD"),
		OldPassword: "changeme",
	}
}
