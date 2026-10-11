package ingestion

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RecoveryUnaryInterceptor turns a panic in a unary handler (Enroll) into
// a codes.Internal error for that call, and logs it with its stack. Without
// it, one malformed request that reaches a bug would stop the whole server.
func RecoveryUnaryInterceptor(logger *zap.Logger) grpc.UnaryServerInterceptor {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer recoverHandler(logger, info.FullMethod, &err)
		return handler(ctx, req)
	}
}

// RecoveryStreamInterceptor does the same for a streaming handler
// (StreamEvents): the panicking stream ends with codes.Internal, and the
// server and every other stream keep running. The bus reconnects.
func RecoveryStreamInterceptor(logger *zap.Logger) grpc.StreamServerInterceptor {
	if logger == nil {
		logger = zap.NewNop()
	}
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer recoverHandler(logger, info.FullMethod, &err)
		return handler(srv, ss)
	}
}

// recoverHandler is deferred around a handler. On a panic it logs the value
// and the stack and sets *err; the panic value is not sent to the client.
func recoverHandler(logger *zap.Logger, method string, err *error) {
	if r := recover(); r != nil {
		logger.Error("panic in gRPC handler; the call failed and the server keeps running",
			zap.String("method", method),
			zap.Any("panic", r),
			zap.Stack("stack"),
		)
		*err = status.Error(codes.Internal, "internal server error")
	}
}
