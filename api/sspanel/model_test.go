package sspanel_test

import (
	"encoding/json"
	"testing"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/sspanel"
)

// TestCustomConfigPanelNestedFormat 覆盖面板下拉的嵌套写法：
// 数字端口、reality / xhttp 嵌套对象、只给 security: reality。
func TestCustomConfigPanelNestedFormat(t *testing.T) {
	data := []byte(`{
		"offset_port_node": 443,
		"network": "xhttp",
		"security": "reality",
		"reality": {
			"server_name": "www.microsoft.com",
			"public_key": "public-key",
			"short_id": "abcd",
			"fingerprint": "chrome",
			"spider_x": "/"
		},
		"xhttp": {"path": "/xxx", "host": "a.example.com", "mode": "auto"}
	}`)

	config := new(sspanel.CustomConfig)
	if err := json.Unmarshal(data, config); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}

	if config.OffsetPortNode != "443" {
		t.Errorf("OffsetPortNode = %q, want %q", config.OffsetPortNode, "443")
	}
	if config.Network != "xhttp" || config.Security != "reality" {
		t.Errorf("Network/Security = %q/%q, want xhttp/reality", config.Network, config.Security)
	}
	if config.Path != "/xxx" || config.Host != "a.example.com" || config.Mode != "auto" {
		t.Errorf("xhttp hoist failed: path=%q host=%q mode=%q", config.Path, config.Host, config.Mode)
	}
	if !config.EnableREALITY {
		t.Error("EnableREALITY should be inferred from security=reality")
	}
	if config.RealityOpts == nil {
		t.Fatal("RealityOpts should not be nil")
	}
	if len(config.RealityOpts.ServerNames) != 1 || config.RealityOpts.ServerNames[0] != "www.microsoft.com" {
		t.Errorf("ServerNames = %v, want [www.microsoft.com]", config.RealityOpts.ServerNames)
	}
	if len(config.RealityOpts.ShortIds) != 1 || config.RealityOpts.ShortIds[0] != "abcd" {
		t.Errorf("ShortIds = %v, want [abcd]", config.RealityOpts.ShortIds)
	}
	if config.RealityOpts.Dest != "www.microsoft.com:443" {
		t.Errorf("Dest = %q, want www.microsoft.com:443", config.RealityOpts.Dest)
	}
}

// TestCustomConfigStandardFormat 确认原有 XrayR 标准写法不受影响。
func TestCustomConfigStandardFormat(t *testing.T) {
	data := []byte(`{
		"offset_port_node": "8443",
		"network": "ws",
		"security": "tls",
		"host": "hk.domain.com",
		"path": "/v2ray",
		"enable_vless": "1"
	}`)

	config := new(sspanel.CustomConfig)
	if err := json.Unmarshal(data, config); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}

	if config.OffsetPortNode != "8443" || config.Network != "ws" || config.Security != "tls" {
		t.Errorf("basic fields = %q/%q/%q", config.OffsetPortNode, config.Network, config.Security)
	}
	if config.Host != "hk.domain.com" || config.Path != "/v2ray" {
		t.Errorf("Host/Path = %q/%q", config.Host, config.Path)
	}
	if config.EnableVless != "1" {
		t.Errorf("EnableVless = %q, want 1", config.EnableVless)
	}
	if config.EnableREALITY {
		t.Error("EnableREALITY should stay false when security=tls")
	}
}

// TestCustomConfigPanelTLSObject 覆盖面板把 tls 写成对象（客户端参数）的写法。
func TestCustomConfigPanelTLSObject(t *testing.T) {
	data := []byte(`{
		"offset_port_node": "8443",
		"offset_port_user": "443",
		"network": "xhttp",
		"security": "tls",
		"host": "a030.517998.xyz",
		"path": "/a7f3c9",
		"mode": "auto",
		"tls": {
			"server_name": "a030.517998.xyz",
			"fingerprint": "chrome",
			"allow_insecure": false,
			"alpn": ["h2", "http/1.1"]
		},
		"xhttp": {"path": "/a7f3c9", "host": "a030.517998.xyz", "mode": "auto"},
		"enable_vless": "1"
	}`)

	config := new(sspanel.CustomConfig)
	if err := json.Unmarshal(data, config); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}

	if config.OffsetPortNode != "8443" || config.Network != "xhttp" || config.Security != "tls" {
		t.Errorf("basic fields = %q/%q/%q", config.OffsetPortNode, config.Network, config.Security)
	}
	if config.Path != "/a7f3c9" || config.Host != "a030.517998.xyz" || config.Mode != "auto" {
		t.Errorf("xhttp hoist failed: path=%q host=%q mode=%q", config.Path, config.Host, config.Mode)
	}
	if config.EnableVless != "1" {
		t.Errorf("EnableVless = %q, want 1", config.EnableVless)
	}
	if config.TLS != "" {
		t.Errorf("TLS should be dropped for object form, got %q", config.TLS)
	}
}

// TestParseUserListSkipsEmptyUUID 空 UUID 用户应被跳过，避免整个节点因 invalid UUID 退出。
func TestParseUserListSkipsEmptyUUID(t *testing.T) {
	client := sspanel.New(&api.Config{
		APIHost:  "http://127.0.0.1",
		Key:      "key",
		NodeID:   1,
		NodeType: "V2ray",
	})

	users := []sspanel.UserResponse{
		{ID: 1, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811"},
		{ID: 2, UUID: ""},
		{ID: 3, UUID: "   "},
	}

	list, err := client.ParseUserListResponse(&users)
	if err != nil {
		t.Fatalf("parse user list failed: %s", err)
	}
	if len(*list) != 1 {
		t.Fatalf("got %d users, want 1", len(*list))
	}
	if (*list)[0].UID != 1 {
		t.Errorf("UID = %d, want 1", (*list)[0].UID)
	}
}

// TestCustomConfigDottedRealityOpts 覆盖 reality-opts 点号键与字符串布尔写法。
func TestCustomConfigDottedRealityOpts(t *testing.T) {
	data := []byte(`{
		"offset_port_node": "443",
		"network": "tcp",
		"enable_reality": "on",
		"reality-opts.private_key": "private-key",
		"reality-opts.server_names": ["a.example.com"],
		"allow_insecure": true
	}`)

	config := new(sspanel.CustomConfig)
	if err := json.Unmarshal(data, config); err != nil {
		t.Fatalf("unmarshal failed: %s", err)
	}

	if !config.EnableREALITY {
		t.Error("EnableREALITY should be true for \"on\"")
	}
	if config.RealityOpts == nil || config.RealityOpts.PrivateKey != "private-key" {
		t.Errorf("private_key not merged: %+v", config.RealityOpts)
	}
	if len(config.RealityOpts.ServerNames) != 1 || config.RealityOpts.ServerNames[0] != "a.example.com" {
		t.Errorf("ServerNames = %v", config.RealityOpts.ServerNames)
	}
	if config.AllowInsecure != "1" {
		t.Errorf("AllowInsecure = %q, want 1", config.AllowInsecure)
	}
}
