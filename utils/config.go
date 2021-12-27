package utils

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	DBString          string `mapstructure:"DBSTRING"`
	PORT              string `mapstructure:"PORT"`
	DOMAIN            string `mapstructure:"DOMAIN"`
	MailgunAPIKey     string `mapstructure:"MAILGUNAPIKEY"`
	Access_Token_Key  string `mapstructure:"ACCESS_TOKEN_KEY"`
	Refresh_Token_Key string `mapstructure:"REFRESH_TOKEN_KEY"`
}

func LoadConfig(path string) (config Config, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	err = viper.ReadInConfig()

	if err != nil {
		fmt.Println(err)
	}

	err = viper.Unmarshal(&config)
	return
}
