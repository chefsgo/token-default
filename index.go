package token_default

import (
	"github.com/chefsgo/chef"
)

func Driver() chef.TokenDriver {
	return &defaultTokenDriver{}
}

func init() {
	chef.Register("default", Driver())
}
