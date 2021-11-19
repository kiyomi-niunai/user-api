package svc

import (
	"api/internal/config"
	"github.com/kiyomi-niunai/user/userclient"
	"github.com/tal-tech/go-zero/zrpc"
)

type ServiceContext struct {
	Config config.Config
	UserRpc userclient.User
}

func NewServiceContext(c config.Config) *ServiceContext {
	return &ServiceContext{
		Config: c,
		UserRpc: userclient.NewUser(zrpc.MustNewClient(c.UserRpc)),
	}
}
