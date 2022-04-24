package token_default

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chefsgo/chef"
	"github.com/chefsgo/token"
)

var (
	errInvalidTokenData = errors.New("Invalid token data.")
)

type (
	defaultDriver  struct{}
	defaultConnect struct {
		config  token.Config
		setting defaultSetting
	}
	defaultSetting struct {
	}
)

//连接
func (driver *defaultDriver) Connect(config token.Config) (token.Connect, error) {
	setting := defaultSetting{}
	return &defaultConnect{
		config: config, setting: setting,
	}, nil
}

//打开连接
func (connect *defaultConnect) Open() error {
	return nil
}

//关闭连接
func (connect *defaultConnect) Close() error {
	return nil
}

//------------- token begin ------------------------------

//签名格式	id/auth/info/expiry/load
func (connect *defaultConnect) Sign(data *token.Token) (string, error) {
	if data.Expiry < 0 {
		data.Expiry = 0
	}

	authed := int64(0)
	if data.Authorized {
		authed = 1
	}
	id, err := chef.DecryptDIGIT(data.ActId)
	if err != nil {
		return "", err
	}

	nums := []int64{
		authed, id, data.Expiry,
	}

	numsText, err := chef.EncryptDIGITS(nums)
	if err != nil {
		return "", err
	}

	payload := ""
	if data.Payload != nil {
		if vv, err := chef.MarshalJSON(data.Payload); err == nil {
			payload = string(vv)
		}
	}

	raw := fmt.Sprintf("%v\t%v\t%v", numsText, data.Identity, payload)

	hash, err := chef.EncryptTEXT(raw)
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

func (connect *defaultConnect) Validate(tokenStr string) (*token.Token, error) {
	alls := strings.Split(tokenStr, ".")
	if len(alls) != 2 {
		return nil, errInvalidTokenData
	}
	//验证签名
	err := hmacVerify(alls[0], alls[1], connect.config.Secret)
	if err != nil {
		return nil, err
	}

	//处理原数据
	raw, err := chef.DecryptTEXT(alls[0])
	if err != nil {
		return nil, err
	}

	//分割字串
	raws := strings.Split(raw, "\t")
	if len(raws) != 3 {
		return nil, errInvalidTokenData
	}

	//得到数字列表
	nums, err := chef.DecryptDIGITS(raws[0])
	if err != nil {
		return nil, err
	}
	if len(nums) != 3 {
		return nil, errInvalidTokenData
	}

	now := time.Now()

	//data
	data := &token.Token{
		Identity: raws[1],
		Expiry:   nums[2],
	}

	//是否校验，并且在有效期以内
	if nums[0] > 0 && now.Unix() < data.Expiry {
		data.Authorized = true
	}

	//解析payload
	if raws[2] != "" {
		err = chef.UnmarshalJSON([]byte(raws[2]), &data.Payload)
		if err != nil {
			return nil, err
		}
	}

	//编码ID
	id, err := chef.EncryptDIGIT(nums[1])
	if err == nil {
		data.ActId = id
	}

	return data, nil
}

//------------- token end ------------------------------
