package xrpc

import (
	"context"
	"fmt"

	loggerpb "github.com/xtls/xray-core/app/log/command"
	handlerpb "github.com/xtls/xray-core/app/proxyman/command"
	statspb "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Clients groups the gRPC stubs that the samples rely on.
type Clients struct {
	Connection *grpc.ClientConn
	Handler    handlerpb.HandlerServiceClient
	Logger     loggerpb.LoggerServiceClient
	Stats      statspb.StatsServiceClient
}

// New establishes an insecure (plaintext) connection against a running Xray API endpoint.
func New(ctx context.Context, addr string, port uint16, dialOpts ...grpc.DialOption) (*Clients, error) {
	target := fmt.Sprintf("%s:%d", addr, port)
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	opts = append(opts, dialOpts...)

	conn, err := grpc.DialContext(ctx, target, opts...)
	if err != nil {
		return nil, err
	}

	return &Clients{
		Connection: conn,
		Handler:    handlerpb.NewHandlerServiceClient(conn),
		Logger:     loggerpb.NewLoggerServiceClient(conn),
		Stats:      statspb.NewStatsServiceClient(conn),
	}, nil
}
