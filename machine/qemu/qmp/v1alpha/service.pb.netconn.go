// Code generated by kraftkit.sh/tools/protoc-gen-go-netconn. DO NOT EDIT.
// source: machine/qemu/qmp/v1alpha/service.proto

package qmpv1alpha

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sync"
)

type QEMUMachineProtocolClient struct {
	conn io.ReadWriteCloser
	lock sync.RWMutex
	recv *bufio.Reader
	send *bufio.Writer
}

func NewQEMUMachineProtocolClient(conn io.ReadWriteCloser) *QEMUMachineProtocolClient {
	return &QEMUMachineProtocolClient{
		conn: conn,
		recv: bufio.NewReader(conn),
		send: bufio.NewWriter(conn),
	}
}

func (c *QEMUMachineProtocolClient) Close() error {
	return c.conn.Close()
}

func (c *QEMUMachineProtocolClient) setRpcRequestSetDefaults(face any) error {
	v := reflect.ValueOf(face)

	// If it's an interface or a pointer, unwrap it.
	if v.Kind() == reflect.Ptr && v.Elem().Kind() == reflect.Struct {
		v = v.Elem()
	} else {
		return nil
	}

	t := reflect.TypeOf(v.Interface())

	for i := 0; i < v.NumField(); i++ {
		def := t.Field(i).Tag.Get("default")
		if def == "" {
			continue
		}

		f := v.FieldByName(t.Field(i).Name)
		if !f.IsValid() || !f.CanSet() {
			continue
		}

		switch f.Kind() {
		case reflect.String:
			f.SetString(def)
		default:
			return fmt.Errorf("unsupported default kind: %s", f.Kind().String())
		}
	}

	return nil
}

func (c *QEMUMachineProtocolClient) Greeting() (*GreetingResponse, error) {
	var b []byte
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	var res GreetingResponse
	b, err = c.recv.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

func (c *QEMUMachineProtocolClient) Quit(req QuitRequest) (*QuitResponse, error) {
	var b []byte
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.setRpcRequestSetDefaults(&req); err != nil {
		return nil, err
	}

	b, err = json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.send.Write(append(b, '\x0a')); err != nil {
		return nil, err
	}
	if err := c.send.Flush(); err != nil {
		return nil, err
	}

	var res QuitResponse
	b, err = c.recv.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

func (c *QEMUMachineProtocolClient) Stop(req StopRequest) (*any, error) {
	var b []byte
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.setRpcRequestSetDefaults(&req); err != nil {
		return nil, err
	}

	b, err = json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.send.Write(append(b, '\x0a')); err != nil {
		return nil, err
	}
	if err := c.send.Flush(); err != nil {
		return nil, err
	}

	var res any
	b, err = c.recv.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

func (c *QEMUMachineProtocolClient) Cont(req ContRequest) (*any, error) {
	var b []byte
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.setRpcRequestSetDefaults(&req); err != nil {
		return nil, err
	}

	b, err = json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.send.Write(append(b, '\x0a')); err != nil {
		return nil, err
	}
	if err := c.send.Flush(); err != nil {
		return nil, err
	}

	var res any
	b, err = c.recv.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

func (c *QEMUMachineProtocolClient) Capabilities(req CapabilitiesRequest) (*CapabilitiesResponse, error) {
	var b []byte
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.setRpcRequestSetDefaults(&req); err != nil {
		return nil, err
	}

	b, err = json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.send.Write(append(b, '\x0a')); err != nil {
		return nil, err
	}
	if err := c.send.Flush(); err != nil {
		return nil, err
	}

	var res CapabilitiesResponse
	b, err = c.recv.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

func (c *QEMUMachineProtocolClient) QueryKvm(req QueryKvmRequest) (*QueryKvmResponse, error) {
	var b []byte
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.setRpcRequestSetDefaults(&req); err != nil {
		return nil, err
	}

	b, err = json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.send.Write(append(b, '\x0a')); err != nil {
		return nil, err
	}
	if err := c.send.Flush(); err != nil {
		return nil, err
	}

	var res QueryKvmResponse
	b, err = c.recv.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	return &res, nil
}

func (c *QEMUMachineProtocolClient) QueryStatus(req QueryStatusRequest) (*QueryStatusResponse, error) {
	var b []byte
	var err error

	c.lock.Lock()
	defer c.lock.Unlock()

	if err := c.setRpcRequestSetDefaults(&req); err != nil {
		return nil, err
	}

	b, err = json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if _, err := c.send.Write(append(b, '\x0a')); err != nil {
		return nil, err
	}
	if err := c.send.Flush(); err != nil {
		return nil, err
	}

	var res QueryStatusResponse
	b, err = c.recv.ReadBytes('\n')
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, err
	}

	return &res, nil
}
