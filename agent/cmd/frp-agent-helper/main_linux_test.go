//go:build linux

package main

import (
	"context"
	"testing"

	"github.com/frp-admin/frp-admin/agent/internal/roothelper"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
)

func TestExecuteRequestRecoversPanicAndReturnsMutationToken(t *testing.T) {
	mutation := make(chan struct{}, 1)
	mutation <- struct{}{}
	panicHandler := func(context.Context, roothelper.Request) roothelper.Response {
		panic("unexpected helper panic")
	}
	response := executeRequest(context.Background(), mutation, panicHandler, roothelper.Request{Operation: roothelper.OperationProbeService})
	if response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_INTERNAL || response.Diagnostic != "privileged helper request failed" {
		t.Fatalf("response=%+v", response)
	}
	if len(mutation) != 1 {
		t.Fatalf("mutation token count=%d want=1", len(mutation))
	}
	response = executeRequest(context.Background(), mutation, func(context.Context, roothelper.Request) roothelper.Response {
		return roothelper.Response{Changed: true}
	}, roothelper.Request{Operation: roothelper.OperationProbeService})
	if !response.Changed || len(mutation) != 1 {
		t.Fatalf("second response=%+v token count=%d", response, len(mutation))
	}
}

func TestExecuteRequestContextFailureDoesNotCreateToken(t *testing.T) {
	mutation := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := executeRequest(ctx, mutation, func(context.Context, roothelper.Request) roothelper.Response {
		t.Fatal("handler ran without mutation token")
		return roothelper.Response{}
	}, roothelper.Request{})
	if response.ErrorCode != agentv1.ErrorCode_ERROR_CODE_INTERNAL || len(mutation) != 0 {
		t.Fatalf("response=%+v token count=%d", response, len(mutation))
	}
}
