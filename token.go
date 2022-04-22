package token_default

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chefsgo/chef"
)

var (
	errInvalidTokenData = errors.New("Invalid token data.")
)

type (
	defaultTokenDriver  struct{}
	defaultTokenConnect struct {
		config  chef.TokenConfig
		setting defaultTokenSetting
	}
	defaultTokenSetting struct {
	}
)

//连接
func (driver *defaultTokenDriver) Connect(config chef.TokenConfig) (chef.TokenConnect, error) {
	setting := defaultTokenSetting{}
	return &defaultTokenConnect{
		config: config, setting: setting,
	}, nil
}

//打开连接
func (connect *defaultTokenConnect) Open() error {
	return nil
}

//关闭连接
func (connect *defaultTokenConnect) Close() error {
	return nil
}

//------------- token begin ------------------------------

//签名格式	id/auth/info/expiry/load
func (connect *defaultTokenConnect) Sign(token *chef.Token, expiry time.Duration) (string, error) {
	now := time.Now()

	if expiry > 0 {
		token.Expiry = now.Add(expiry).Unix()
	}

	authed := int64(0)
	if token.Authorized {
		authed = 1
	}
	id, err := chef.DigitDecrypt(token.ActId)
	if err != nil {
		return "", err
	}

	nums := []int64{
		authed, id, token.Expiry,
	}

	numsText, err := chef.DigitsEncrypt(nums)
	if err != nil {
		return "", err
	}

	payload := ""
	if token.Payload != nil {
		if vv, err := chef.JSONMarshal(token.Payload); err == nil {
			payload = string(vv)
		}
	}

	raw := fmt.Sprintf("%v\t%v\t%v", numsText, token.Identity, payload)

	hash, err := chef.TextEncrypt(raw)
	if err != nil {
		return "", err
	}

	//计算签名
	sign, err := hmacSign(hash, connect.config.Secret)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s.%s", hash, sign), nil
}

func (connect *defaultTokenConnect) Validate(token string) (*chef.Token, error) {
	alls := strings.Split(token, ".")
	if len(alls) != 2 {
		return nil, errInvalidTokenData
	}
	//验证签名
	err := hmacVerify(alls[0], alls[1], connect.config.Secret)
	if err != nil {
		return nil, err
	}

	//处理原数据
	raw, err := chef.TextDecrypt(alls[0])
	if err != nil {
		return nil, err
	}

	//分割字串
	raws := strings.Split(raw, "\t")
	if len(raws) != 3 {
		return nil, errInvalidTokenData
	}

	//得到数字列表
	nums, err := chef.DigitsDecrypt(raws[0])
	if err != nil {
		return nil, err
	}
	if len(nums) != 3 {
		return nil, errInvalidTokenData
	}

	now := time.Now()

	//data
	data := &chef.Token{
		Identity: raws[1],
		Expiry:   nums[2],
	}

	//是否校验，并且在有效期以内
	if nums[0] > 0 && now.Unix() < data.Expiry {
		data.Authorized = true
	}

	//解析payload
	if raws[2] != "" {
		err = chef.JSONUnmarshal([]byte(raws[2]), &data.Payload)
		if err != nil {
			return nil, err
		}
	}

	//编码ID
	id, err := chef.DigitEncrypt(nums[1])
	if err == nil {
		data.ActId = id
	}

	return data, nil
}

//------------- token end ------------------------------
