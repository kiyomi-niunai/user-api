package logic

import (
	"context"
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/kiyomi-niunai/user/userclient"
	"strconv"
	"strings"
	"time"

	"api/internal/svc"
	"api/internal/types"

	"github.com/tal-tech/go-zero/core/logx"
)

type LoginLogic struct {
	logx.Logger
	ctx    context.Context
	svcCtx *svc.ServiceContext
}

// Token token认证
type Token struct {
	AppID     string
	AppSecret string
}

func NewLoginLogic(ctx context.Context, svcCtx *svc.ServiceContext) LoginLogic {
	return LoginLogic{
		Logger: logx.WithContext(ctx),
		ctx:    ctx,
		svcCtx: svcCtx,
	}
}

func (l *LoginLogic) Login(req types.LoginReq) (*types.LoginReply, error) {
	if len(strings.TrimSpace(req.Username)) == 0 || len(strings.TrimSpace(req.Password)) == 0 {
		return nil, errors.New("参数错误")
	}
	userInfo, err := l.svcCtx.UserRpc.GetUser(l.ctx, &userclient.IdRequest{
		Id: strconv.Itoa(int(req.Id)),
	})
	if err != nil{
		return nil, errors.New("获取用户失败")
	}
	// ---start---
	now := time.Now().Unix()
	accessExpire := l.svcCtx.Config.Auth.AccessExpire
	idInt, _ := strconv.Atoi(userInfo.Id)
	jwtToken, err := l.getJwtToken(l.svcCtx.Config.Auth.AccessSecret, now, l.svcCtx.Config.Auth.AccessExpire, int64(idInt))
	if err != nil {
		return nil, err
	}
	// ---end---

	id, _ := strconv.Atoi(userInfo.Id)
	return &types.LoginReply{
		Id:           int64(id),
		Name:         userInfo.Name,
		Gender:       userInfo.Gender,
		AccessToken:  jwtToken,
		AccessExpire: now + accessExpire,
		RefreshAfter: now + accessExpire/2,
	}, nil
}

func (l *LoginLogic) getJwtToken(secretKey string, iat, seconds, userId int64) (string, error) {
	claims := make(jwt.MapClaims)
	claims["exp"] = iat + seconds
	claims["iat"] = iat
	claims["userId"] = userId
	token := jwt.New(jwt.SigningMethodHS512)
	token.Claims = claims
	return token.SignedString([]byte(secretKey))
}
