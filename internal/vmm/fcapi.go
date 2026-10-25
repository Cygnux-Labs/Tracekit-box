package vmm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// apiClient speaks Firecracker's REST API over its unix socket. Firecracker serves one request at a time.
type apiClient struct {
	hc *http.Client
	tr *http.Transport
}

const (
	apiRequestTimeout = 10 * time.Second // per request when ctx has no earlier deadline
	apiMaxBody        = 64 << 10         // response bodies are small JSON; anything bigger is cut
)

func newAPIClient(sock string) *apiClient {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
		DisableCompression:  true,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     30 * time.Second,
	}
	return &apiClient{hc: &http.Client{Transport: tr}, tr: tr}
}

func (c *apiClient) close() { c.tr.CloseIdleConnections() }

// do sends one request and returns the response body of a 2xx reply. Any other status is an error carrying
// Firecracker's fault_message.
func (c *apiClient) do(ctx context.Context, method, path string, body any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, apiRequestTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("firecracker API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, apiMaxBody))
	if err != nil {
		return nil, fmt.Errorf("firecracker API %s %s: read reply: %w", method, path, err)
	}
	if resp.StatusCode/100 == 2 {
		return b, nil
	}
	var fault struct {
		FaultMessage string `json:"fault_message"`
	}
	msg := strings.TrimSpace(string(b))
	if json.Unmarshal(b, &fault) == nil && fault.FaultMessage != "" {
		msg = fault.FaultMessage
	}
	if msg == "" {
		msg = "no fault message"
	}
	return nil, fmt.Errorf("firecracker API %s %s: %s (HTTP %d)", method, path, msg, resp.StatusCode)
}

func (c *apiClient) put(ctx context.Context, path string, body any) error {
	_, err := c.do(ctx, http.MethodPut, path, body)
	return err
}

func (c *apiClient) patch(ctx context.Context, path string, body any) error {
	_, err := c.do(ctx, http.MethodPatch, path, body)
	return err
}

// Firecracker API bodies (only the fields we set).

type fcBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type fcDrive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type fcMachineConfig struct {
	VCPUCount  int `json:"vcpu_count"`
	MemSizeMiB int `json:"mem_size_mib"`
}

type fcVsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

type fcAction struct {
	ActionType string `json:"action_type"`
}

type fcVM struct {
	State string `json:"state"`
}
