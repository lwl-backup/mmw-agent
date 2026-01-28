package handler

import (
	"context"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vmess"
)

// AddVMessUser demonstrates AlterInbound(AddUserOperation) for VMess.
func AddVMessUser(ctx context.Context, client command.HandlerServiceClient, inboundTag, email string) error {
	req := &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Level: 0,
				Email: email,
				Account: serial.ToTypedMessage(&vmess.Account{
					Id: randomUUID(),
					SecuritySettings: &protocol.SecurityConfig{
						Type: protocol.SecurityType_AUTO,
					},
				}),
			},
		}),
	}
	_, err := client.AlterInbound(ctx, req)
	return err
}

// AddVLESSUser shows how to add VLESS users dynamically.
func AddVLESSUser(ctx context.Context, client command.HandlerServiceClient, inboundTag, email string) error {
	req := &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Level: 0,
				Email: email,
				Account: serial.ToTypedMessage(&vless.Account{
					Id:         randomUUID(),
					Encryption: "none",
				}),
			},
		}),
	}
	_, err := client.AlterInbound(ctx, req)
	return err
}

// AddTrojanUser adds a Trojan password to an inbound handler.
func AddTrojanUser(ctx context.Context, client command.HandlerServiceClient, inboundTag, email, password string) error {
	req := &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Level: 0,
				Email: email,
				Account: serial.ToTypedMessage(&trojan.Account{
					Password: password,
				}),
			},
		}),
	}
	_, err := client.AlterInbound(ctx, req)
	return err
}

// AddShadowsocksUser sets up a Shadowsocks AEAD credential.
func AddShadowsocksUser(ctx context.Context, client command.HandlerServiceClient, inboundTag, email, password string) error {
	req := &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Level: 0,
				Email: email,
				Account: serial.ToTypedMessage(&shadowsocks.Account{
					Password:   password,
					CipherType: shadowsocks.CipherType_CHACHA20_POLY1305,
				}),
			},
		}),
	}
	_, err := client.AlterInbound(ctx, req)
	return err
}

// AddShadowsocks2022User covers key rotation for SS2022.
func AddShadowsocks2022User(ctx context.Context, client command.HandlerServiceClient, inboundTag, email string) error {
	req := &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.AddUserOperation{
			User: &protocol.User{
				Email: email,
				Account: serial.ToTypedMessage(&ss2022.Account{
					Key: randomUUID(),
				}),
			},
		}),
	}
	_, err := client.AlterInbound(ctx, req)
	return err
}

// RemoveUser removes any user (identified by email) from an inbound.
func RemoveUser(ctx context.Context, client command.HandlerServiceClient, inboundTag, email string) error {
	req := &command.AlterInboundRequest{
		Tag: inboundTag,
		Operation: serial.ToTypedMessage(&command.RemoveUserOperation{
			Email: email,
		}),
	}
	_, err := client.AlterInbound(ctx, req)
	return err
}
