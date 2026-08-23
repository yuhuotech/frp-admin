//go:build linux

package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/frp-admin/frp-admin/agent/internal/roothelper"
	agentv1 "github.com/frp-admin/frp-admin/contracts/gen/go/frpadmin/agent/v1"
	"golang.org/x/sys/unix"
)

func main() {
	if os.Geteuid() != 0 {
		log.Fatal("frp-agent-helper must run as root")
	}
	config, err := roothelper.LoadConfig("/etc/frp-agent/helper.json")
	if err != nil {
		log.Fatal(err)
	}
	account, err := user.Lookup("frp-agent")
	if err != nil {
		log.Fatal(err)
	}
	allowedUID, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil {
		log.Fatal("frp-agent UID is invalid")
	}
	listeners, err := activationListeners()
	if err != nil || len(listeners) != 1 {
		log.Fatal("exactly one systemd socket is required")
	}
	defer listeners[0].Close()
	server := roothelper.Server{Config: config}
	mutation := make(chan struct{}, 1)
	mutation <- struct{}{}
	for {
		connection, acceptErr := listeners[0].Accept()
		if acceptErr != nil {
			log.Fatal(acceptErr)
		}
		go serveConnection(connection, allowedUID, mutation, server.Handle)
	}
}

func serveConnection(connection net.Conn, allowedUID uint64, mutation chan struct{}, handle func(context.Context, roothelper.Request) roothelper.Response) {
	authorized, responded := false, false
	defer connection.Close()
	defer func() {
		if recover() != nil && authorized && !responded {
			_ = json.NewEncoder(connection).Encode(internalFailure())
		}
	}()
	_ = connection.SetDeadline(time.Now().Add(50 * time.Second))
	if uid, credentialErr := peerUID(connection); credentialErr != nil || uint64(uid) != allowedUID {
		return
	}
	authorized = true
	decoder := json.NewDecoder(io.LimitReader(connection, 17<<20))
	decoder.DisallowUnknownFields()
	var request roothelper.Request
	if decoder.Decode(&request) != nil {
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	response := executeRequest(ctx, mutation, handle, request)
	state := ""
	if response.ServiceStatus != nil {
		state = response.ServiceStatus.GetState().String()
	}
	log.Printf("operation=%s error_code=%s service_state=%s", request.Operation, response.ErrorCode.String(), state)
	if json.NewEncoder(connection).Encode(response) == nil {
		responded = true
	}
}

func executeRequest(ctx context.Context, mutation chan struct{}, handle func(context.Context, roothelper.Request) roothelper.Response, request roothelper.Request) (response roothelper.Response) {
	select {
	case <-ctx.Done():
		return internalFailure()
	case <-mutation:
	}
	defer func() { mutation <- struct{}{} }()
	defer func() {
		if recover() != nil {
			response = internalFailure()
		}
	}()
	return handle(ctx, request)
}

func internalFailure() roothelper.Response {
	return roothelper.Response{ErrorCode: agentv1.ErrorCode_ERROR_CODE_INTERNAL, Diagnostic: "privileged helper request failed"}
}

func activationListeners() ([]net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, os.ErrInvalid
	}
	file := os.NewFile(3, "frp-agent-helper.socket")
	listener, err := net.FileListener(file)
	return []net.Listener{listener}, err
}

func peerUID(connection net.Conn) (uint32, error) {
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return 0, os.ErrInvalid
	}
	raw, err := unixConnection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var socketErr error
	err = raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	return credential.Uid, nil
}
