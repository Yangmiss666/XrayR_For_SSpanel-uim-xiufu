package sspanel

import (
	"encoding/json"
	"strings"
)

// NodeInfoResponse is the response of node
type NodeInfoResponse struct {
	Group           int             `json:"node_group"`
	Class           int             `json:"node_class"`
	SpeedLimit      float64         `json:"node_speedlimit"`
	TrafficRate     float64         `json:"traffic_rate"`
	Sort            int             `json:"sort"`
	RawServerString string          `json:"server"`
	Type            string          `json:"type"`
	CustomConfig    json.RawMessage `json:"custom_config"`
	Version         string          `json:"version"`
}

type CustomConfig struct {
	OffsetPortNode string          `json:"offset_port_node"`
	Host           string          `json:"host"`
	Method         string          `json:"method"`
	ServerKey      string          `json:"server_key"`
	TLS            string          `json:"tls"`
	EnableVless    string          `json:"enable_vless"`
	Network        string          `json:"network"`
	Security       string          `json:"security"`
	Path           string          `json:"path"`
	Mode           string          `json:"mode"` // xhttp / splithttp 模式: auto, packet-up, stream-up, stream-one
	VerifyCert     bool            `json:"verify_cert"`
	Obfs           string          `json:"obfs"`
	Header         json.RawMessage `json:"header"`
	AllowInsecure  string          `json:"allow_insecure"`
	Servicename    string          `json:"servicename"`
	EnableXtls     string          `json:"enable_xtls"`
	Flow           string          `json:"flow"`
	EnableREALITY  bool            `json:"enable_reality"`
	RealityOpts    *REALITYConfig  `json:"reality-opts"`
	// REALITY 平铺兼容字段：reality-opts 中缺失或为零值的字段回退到这里取。
	// 平铺也没有时，再由 controller 回退到本地 config.yml 的 REALITYConfigs 默认值。
	Show                  bool          `json:"show"`                  // 平铺 show
	ShortId               string        `json:"shortId"`               // 平铺 shortId → ShortIds
	Sni                   string        `json:"sni"`                   // 平铺 sni → ServerNames / Dest
	Dest                  string        `json:"dest"`                  // 平铺 dest
	ServerNames           []string      `json:"serverNames"`           // 平铺 serverNames
	ShortIds              []string      `json:"shortIds"`              // 平铺 shortIds
	PrivateKey            string        `json:"privateKey"`            // 平铺 privateKey
	ProxyProtocolVer      uint64        `json:"proxyProtocolVer"`      // 平铺 proxyProtocolVer
	MinClientVer          string        `json:"minClientVer"`          // 平铺 minClientVer
	MaxClientVer          string        `json:"maxClientVer"`          // 平铺 maxClientVer
	MaxTimeDiff           uint64        `json:"maxTimeDiff"`           // 平铺 maxTimeDiff
	Mldsa65Seed           string        `json:"mldsa65Seed"`           // 平铺 mldsa65Seed
	LimitFallbackUpload   LimitFallback `json:"limitFallbackUpload"`   // 平铺 limitFallbackUpload
	LimitFallbackDownload LimitFallback `json:"limitFallbackDownload"` // 平铺 limitFallbackDownload
}

// UnmarshalJSON 在标准解析前做一次兼容处理，用于吃下各面板不一致的写法：
//  1. 把 "reality-opts.private_key" 这类点号平铺键归并成嵌套的 reality-opts 对象，
//     嵌套对象里已有的字段优先，点号键只补齐缺失项；
//  2. 把 enable_reality / verify_cert 的 "true" / "1" / "on" 等字符串写法归一成布尔值。
func (c *CustomConfig) UnmarshalJSON(data []byte) error {
	// 用别名类型避免递归调用本方法
	type plain CustomConfig

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// 部分面板把端口下发成数字（如 "offset_port_node": 443），这里统一归一成字符串
	if v, ok := raw["offset_port_node"]; ok {
		raw["offset_port_node"] = normalizeJSONScalarToString(v)
	}

	const realityOptsPrefix = "reality-opts."

	// 先取出已经写成嵌套对象的 reality-opts
	opts := map[string]json.RawMessage{}
	if v, ok := raw["reality-opts"]; ok {
		if err := json.Unmarshal(v, &opts); err != nil {
			opts = map[string]json.RawMessage{}
		}
	}

	// 再把 "reality-opts.xxx" 点号键并入，已存在的字段不覆盖
	merged := false
	for k, v := range raw {
		field, ok := strings.CutPrefix(k, realityOptsPrefix)
		if !ok {
			continue
		}
		merged = true
		delete(raw, k)
		if _, exists := opts[field]; !exists {
			opts[field] = v
		}
	}

	// 部分面板会直接沿用 reality-opts 内的键名平铺下发（如 private_key / server_names）
	for _, field := range realityFlatSnakeKeys {
		v, ok := raw[field]
		if !ok {
			continue
		}
		delete(raw, field)
		if _, exists := opts[field]; exists {
			continue
		}
		merged = true
		opts[field] = v
	}

	// SSPanel 等面板把 REALITY 参数放在嵌套的 reality 对象里，并混有 public_key /
	// fingerprint 这类仅供客户端使用的字段。这里只提取服务端需要的字段，按 reality-opts 的键名并入。
	if v, ok := raw["reality"]; ok {
		delete(raw, "reality")
		if nested := parseJSONObject(v); nested != nil {
			merged = mergeNestedREALITY(opts, nested) || merged
		}
	}

	// 面板把 xhttp 参数放在嵌套对象里，而服务端读取的是顶层 path / host / mode
	if v, ok := raw["xhttp"]; ok {
		delete(raw, "xhttp")
		if nested := parseJSONObject(v); nested != nil {
			for _, key := range []string{"path", "host", "mode"} {
				if b, ok := nested[key]; ok {
					if _, exists := raw[key]; !exists {
						raw[key] = b
					}
				}
			}
		}
	}

	// REALITY 面板通常只下发 security: reality，不会额外写 enable_reality
	if v, ok := raw["security"]; ok {
		if strings.EqualFold(strings.Trim(strings.TrimSpace(string(v)), `"`), "reality") {
			if _, exists := raw["enable_reality"]; !exists {
				raw["enable_reality"] = json.RawMessage("true")
			}
		}
	}

	if merged {
		b, err := json.Marshal(opts)
		if err != nil {
			return err
		}
		raw["reality-opts"] = b
	}

	// 布尔字段兼容字符串写法
	for _, key := range []string{"enable_reality", "verify_cert"} {
		if v, ok := raw[key]; ok {
			raw[key] = normalizeJSONBool(v)
		}
	}

	// allow_insecure 字段兼容 bool 写法：面板可能下发 true/false，
	// 但结构体字段是 string，这里统一转成 "1"/"0"，避免反序列化失败。
	if v, ok := raw["allow_insecure"]; ok {
		raw["allow_insecure"] = normalizeJSONBoolToString(v)
	}

	// 面板会把 tls 写成对象（server_name / alpn / fingerprint 等），
	// 这些只是客户端订阅参数，服务端用不到；结构体字段是 string，
	// 非字符串写法直接丢弃，避免整段 custom_config 解析失败。
	if v, ok := raw["tls"]; ok && !strings.HasPrefix(strings.TrimSpace(string(v)), `"`) {
		delete(raw, "tls")
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, (*plain)(c))
}

// parseJSONObject 解析 JSON 对象；不是对象时返回 nil。
func parseJSONObject(raw json.RawMessage) map[string]json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	return obj
}

// normalizeJSONScalarToString 把数字等标量统一转成 JSON 字符串，字符串原样保留。
func normalizeJSONScalarToString(raw json.RawMessage) json.RawMessage {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return json.RawMessage(`""`)
	}
	if strings.HasPrefix(s, `"`) {
		return raw
	}
	return json.RawMessage(`"` + strings.Trim(s, `"`) + `"`)
}

// jsonStringToArray 把 JSON 字符串转成单元素数组，已经是数组则原样返回。
func jsonStringToArray(raw json.RawMessage) json.RawMessage {
	s := strings.TrimSpace(string(raw))
	if strings.HasPrefix(s, "[") {
		return raw
	}
	if s == "" || s == "null" {
		return json.RawMessage("[]")
	}
	return json.RawMessage("[" + s + "]")
}

// firstJSONArrayString 取 JSON 字符串数组的第一个元素，非数组返回空串。
func firstJSONArrayString(raw json.RawMessage) string {
	var arr []string
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 {
		return ""
	}
	return arr[0]
}

// mergeNestedREALITY 把嵌套 reality 对象的字段按 reality-opts 的键名并入 opts，
// 已存在的字段不覆盖；public_key / fingerprint / spider_x 等仅客户端使用的字段直接忽略。
// 返回值表示是否写入了新字段。
func mergeNestedREALITY(opts, nested map[string]json.RawMessage) bool {
	changed := false
	set := func(key string, value json.RawMessage) {
		if _, exists := opts[key]; exists {
			return
		}
		opts[key] = value
		changed = true
	}

	// server_names：优先数组，其次单值 server_name / sni
	if v, ok := nested["server_names"]; ok {
		set("server_names", jsonStringToArray(v))
	} else if v, ok := nested["server_name"]; ok {
		set("server_names", jsonStringToArray(v))
	} else if v, ok := nested["sni"]; ok {
		set("server_names", jsonStringToArray(v))
	}

	// short_ids：优先数组，其次单值 short_id
	if v, ok := nested["short_ids"]; ok {
		set("short_ids", jsonStringToArray(v))
	} else if v, ok := nested["short_id"]; ok {
		set("short_ids", jsonStringToArray(v))
	}

	for _, key := range []string{
		"private_key",
		"dest",
		"proxy_protocol_ver",
		"min_client_ver",
		"max_client_ver",
		"max_time_diff",
		"show",
		"mldsa65Seed",
		"limit_fallback_upload",
		"limit_fallback_download",
	} {
		if v, ok := nested[key]; ok {
			set(key, v)
		}
	}

	// 面板一般只给 server_name 不给 dest，按 REALITY 惯例用 sni:443 兜底
	if _, exists := opts["dest"]; !exists {
		if names, ok := opts["server_names"]; ok {
			if first := firstJSONArrayString(names); first != "" && !strings.Contains(first, ":") {
				opts["dest"] = json.RawMessage(`"` + first + `:443"`)
				changed = true
			}
		}
	}

	return changed
}

// realityFlatSnakeKeys 是 reality-opts 内部键名被平铺到 custom_config 顶层时的写法。
var realityFlatSnakeKeys = []string{
	"show",
	"dest",
	"proxy_protocol_ver",
	"server_names",
	"private_key",
	"min_client_ver",
	"max_client_ver",
	"max_time_diff",
	"short_ids",
	"mldsa65Seed",
	"limit_fallback_upload",
	"limit_fallback_download",
}

// normalizeJSONBool 把 "true" / "1" / "on" 这类字符串归一成 JSON 布尔字面量；
// 已经是布尔值或无法识别的写法按 false 处理，避免整个 custom_config 解析失败。
func normalizeJSONBool(raw json.RawMessage) json.RawMessage {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(string(raw)), `"`)) {
	case "true", "1", "on", "yes":
		return json.RawMessage("true")
	default:
		return json.RawMessage("false")
	}
}

// normalizeJSONBoolToString 把 true/false 或 "true"/"false"/"1"/"0" 等写法
// 统一归一成字符串 "1" / "0"，用于 allow_insecure 这类 string 字段兼容 bool 输入。
func normalizeJSONBoolToString(raw json.RawMessage) json.RawMessage {
	switch strings.ToLower(strings.Trim(strings.TrimSpace(string(raw)), `"`)) {
	case "true", "1", "on", "yes":
		return json.RawMessage(`"1"`)
	default:
		return json.RawMessage(`"0"`)
	}
}

// UserResponse is the response of user
type UserResponse struct {
	ID          int     `json:"id"`
	Passwd      string  `json:"passwd"`
	Port        uint32  `json:"port"`
	Method      string  `json:"method"`
	SpeedLimit  float64 `json:"node_speedlimit"`
	DeviceLimit int     `json:"node_iplimit"`
	UUID        string  `json:"uuid"`
	AliveIP     int     `json:"alive_ip"`
}

// Response is the common response
type Response struct {
	Ret  uint            `json:"ret"`
	Data json.RawMessage `json:"data"`
}

// PostData is the data structure of post data
type PostData struct {
	Data interface{} `json:"data"`
}

// SystemLoad is the data structure of system load
type SystemLoad struct {
	Uptime string `json:"uptime"`
	Load   string `json:"load"`
}

// OnlineUser is the data structure of online user
type OnlineUser struct {
	UID int    `json:"user_id"`
	IP  string `json:"ip"`
}

// UserTraffic is the data structure of traffic
type UserTraffic struct {
	UID      int   `json:"user_id"`
	Upload   int64 `json:"u"`
	Download int64 `json:"d"`
}

type RuleItem struct {
	ID      int    `json:"id"`
	Content string `json:"regex"`
}

type IllegalItem struct {
	ID  int `json:"list_id"`
	UID int `json:"user_id"`
}

type REALITYConfig struct {
	Show                  bool          `json:"show,omitempty"`
	Dest                  string        `json:"dest,omitempty"`
	ProxyProtocolVer      uint64        `json:"proxy_protocol_ver,omitempty"`
	ServerNames           []string      `json:"server_names,omitempty"`
	PrivateKey            string        `json:"private_key,omitempty"`
	MinClientVer          string        `json:"min_client_ver,omitempty"`
	MaxClientVer          string        `json:"max_client_ver,omitempty"`
	MaxTimeDiff           uint64        `json:"max_time_diff,omitempty"`
	ShortIds              []string      `json:"short_ids,omitempty"`
	Mldsa65Seed           string        `json:"mldsa65Seed,omitempty"`
	LimitFallbackUpload   LimitFallback `json:"limit_fallback_upload,omitempty"`
	LimitFallbackDownload LimitFallback `json:"limit_fallback_download,omitempty"`
}

// LimitFallback limits the traffic that fails REALITY authentication and is
// forwarded to dest. All zeros means no limit.
type LimitFallback struct {
	AfterBytes       uint64 `json:"after_bytes,omitempty"`
	BytesPerSec      uint64 `json:"bytes_per_sec,omitempty"`
	BurstBytesPerSec uint64 `json:"burst_bytes_per_sec,omitempty"`
}
