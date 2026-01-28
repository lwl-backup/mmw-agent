package handler

import (
	"context"

	"github.com/xtls/xray-core/app/proxyman/command"
	cnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/proxy/dokodemo"
	"github.com/xtls/xray-core/proxy/http"
	"github.com/xtls/xray-core/proxy/loopback"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	ss2022 "github.com/xtls/xray-core/proxy/shadowsocks_2022"
	"github.com/xtls/xray-core/proxy/socks"
	"github.com/xtls/xray-core/proxy/trojan"
	"github.com/xtls/xray-core/proxy/vless"
	vlessin "github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vmess"
	vmessin "github.com/xtls/xray-core/proxy/vmess/inbound"
	"github.com/xtls/xray-core/proxy/wireguard"
)

// AddVMessInbound demonstrates HandlerServiceClient.AddInbound for VMess inbound.
func AddVMessInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, true),
		serial.ToTypedMessage(&vmessin.Config{
			User: []*protocol.User{
				{
					Level: 0,
					Email: "demo@vmess.local",
					Account: serial.ToTypedMessage(&vmess.Account{
						Id: randomUUID(),
						SecuritySettings: &protocol.SecurityConfig{
							Type: protocol.SecurityType_AUTO,
						},
					}),
				},
			},
			Default: &vmessin.DefaultConfig{Level: 0},
		}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddVLESSInbound adds a VLESS inbound with Vision style fallbacks.
func AddVLESSInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, true),
		serial.ToTypedMessage(&vlessin.Config{
			Clients: []*protocol.User{
				{
					Level: 1,
					Email: "client@vless.local",
					Account: serial.ToTypedMessage(&vless.Account{
						Id:         randomUUID(),
						Encryption: "none",
					}),
				},
			},
			Fallbacks: []*vlessin.Fallback{
				{
					Name: "websocket",
					Alpn: "h2",
					Path: "/ws",
					Type: "http",
					Dest: "127.0.0.1:8080",
					Xver: 1,
				},
			},
			Decryption: "none",
			Padding:    "enable",
		}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddTrojanInbound registers a Trojan inbound with two users and ALPN fallback.
func AddTrojanInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, true),
		serial.ToTypedMessage(&trojan.ServerConfig{
			Users: []*protocol.User{
				{
					Level: 0,
					Email: "alice@trojan.local",
					Account: serial.ToTypedMessage(&trojan.Account{
						Password: randomUUID(),
					}),
				},
				{
					Level: 0,
					Email: "bob@trojan.local",
					Account: serial.ToTypedMessage(&trojan.Account{
						Password: randomUUID(),
					}),
				},
			},
			Fallbacks: []*trojan.Fallback{
				{
					Name: "http",
					Alpn: "http/1.1",
					Dest: "127.0.0.1:8081",
				},
			},
		}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddShadowsocksInbound adds an AEAD Shadowsocks inbound supporting both TCP and UDP.
func AddShadowsocksInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, false),
		serial.ToTypedMessage(&shadowsocks.ServerConfig{
			Users: []*protocol.User{
				{
					Level: 0,
					Email: "ss@demo.local",
					Account: serial.ToTypedMessage(&shadowsocks.Account{
						Password:   "s3cret-pass",
						CipherType: shadowsocks.CipherType_AES_128_GCM,
					}),
				},
			},
		}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddShadowsocks2022Inbound covers both single user and multi-user deployment.
func AddShadowsocks2022Inbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	server := &ss2022.MultiUserServerConfig{
		Method: "2022-blake3-aes-128-gcm",
		Key:    "0123456789abcdef0123456789abcdef",
		Users: []*protocol.User{
			{
				Level: 0,
				Email: "user1@ss2022.local",
				Account: serial.ToTypedMessage(&ss2022.Account{
					Key: randomUUID(),
				}),
			},
			{
				Level: 0,
				Email: "user2@ss2022.local",
				Account: serial.ToTypedMessage(&ss2022.Account{
					Key: randomUUID(),
				}),
			},
		},
	}
	inbound := inboundConfig(
		tag,
		receiverSettings(port, false),
		serial.ToTypedMessage(server),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddSocksInbound exposes a SOCKS5 server with username/password authentication.
func AddSocksInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, false),
		serial.ToTypedMessage(&socks.ServerConfig{
			AuthType:   socks.AuthType_PASSWORD,
			Accounts:   map[string]string{"demo": "passw0rd"},
			UdpEnabled: true,
			UserLevel:  0,
		}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddHTTPInbound adds an HTTP proxy inbound with basic auth.
func AddHTTPInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, false),
		serial.ToTypedMessage(&http.ServerConfig{
			Accounts:         map[string]string{"demo": "http-pass"},
			AllowTransparent: true,
			UserLevel:        0,
		}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddDokodemoInbound configures a dokodemo-door mirror port.
func AddDokodemoInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32, targetPort uint32) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, false),
		serial.ToTypedMessage(&dokodemo.Config{
			Address:        cnetOrDomain("example.com"),
			Port:           targetPort,
			Networks:       []cnet.Network{cnet.Network_TCP, cnet.Network_UDP},
			FollowRedirect: false,
			UserLevel:      0,
		}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddDNSInbound exposes the built-in DNS server on an API port.
func AddDNSInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, false),
		serial.ToTypedMessage(&dns.Config{
			Server: &cnet.Endpoint{
				Network: cnet.Network_UDP,
				Address: cnetOrDomain("1.1.1.1"),
				Port:    53,
			},
			Non_IPQuery: "drop",
			BlockTypes:  []int32{65, 28},
		}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddLoopbackInbound ties an inbound to an existing outbound chain.
func AddLoopbackInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32, targetInbound string) error {
	inbound := inboundConfig(
		tag,
		receiverSettings(port, false),
		serial.ToTypedMessage(&loopback.Config{InboundTag: targetInbound}),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}

// AddWireGuardInbound sets up a WireGuard entry point with a single peer.
func AddWireGuardInbound(ctx context.Context, client command.HandlerServiceClient, tag string, port uint32) error {
	cfg := &wireguard.DeviceConfig{
		SecretKey:      "yAnExampleSecretKeyBase64==",
		Endpoint:       []string{":51820"},
		Mtu:            1420,
		NumWorkers:     2,
		DomainStrategy: wireguard.DeviceConfig_FORCE_IP46,
		Peers: []*wireguard.PeerConfig{
			{
				PublicKey:  "peerPublicKeyBase64==",
				Endpoint:   "203.0.113.1:51820",
				KeepAlive:  25,
				AllowedIps: []string{"0.0.0.0/0", "::/0"},
			},
		},
	}
	inbound := inboundConfig(
		tag,
		receiverSettings(port, false),
		serial.ToTypedMessage(cfg),
	)
	_, err := client.AddInbound(ctx, &command.AddInboundRequest{Inbound: inbound})
	return err
}
