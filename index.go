package token_default

import (
	"github.com/chefsgo/token"
)

func Driver() token.Driver {
	return &defaultDriver{}
}

func init() {
	token.Register("default", Driver())
}
