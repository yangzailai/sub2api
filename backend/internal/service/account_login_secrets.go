package service

// 上游账号自身的登录口令与 2FA 种子。存放在 Account.Extra（JSONB）里，随备份 JSON 的
// accounts[].extra 一起导入，也可在管理端编辑弹窗里手工录入 / 轮换。
//
// 为什么放 Extra 而不是 Credentials：Credentials 上有 SanitizeStoredCredentials 守卫，
// 它会无条件剥离 "password" 键（Grok Web SSO 换 token 后不允许留存），放进去会静默丢数据。
//
// 安全边界（务必知晓）：
//   - accounts.extra 是明文 JSONB，没有静态加密（SecretEncryptor 只覆盖 TOTP 用户密钥、
//     渠道监控 API Key、插件配置等，不含账号 extra）。
//   - 因此这两个键在响应里必须脱敏，只向前端暴露 has_* 存在性标记。
const (
	// AccountLoginPasswordExtraKey 上游账号登录密码。
	AccountLoginPasswordExtraKey = "password"
	// AccountLoginTOTPSecretExtraKey 上游账号 2FA 的 TOTP 种子（base32，如 JBSWY3DPEHPK3PXP）。
	AccountLoginTOTPSecretExtraKey = "totp_secret"

	// AccountLoginPasswordPresentExtraKey / AccountLoginTOTPSecretPresentExtraKey 是
	// 响应侧派生出的存在性标记，供前端显示「已配置 / 未配置」。它们只出现在响应里，
	// 绝不落库——MergePreservingAccountLoginSecrets 会在入库前剔除。
	AccountLoginPasswordPresentExtraKey   = "has_password"
	AccountLoginTOTPSecretPresentExtraKey = "has_totp_secret"
)

// AccountLoginSecretExtraKeys 列出需要脱敏 + 保留语义的 extra 子键。
var AccountLoginSecretExtraKeys = []string{
	AccountLoginPasswordExtraKey,
	AccountLoginTOTPSecretExtraKey,
}

// accountLoginSecretPresentExtraKeys 是派生标记，入库前必须剔除。
var accountLoginSecretPresentExtraKeys = []string{
	AccountLoginPasswordPresentExtraKey,
	AccountLoginTOTPSecretPresentExtraKey,
}

// presentExtraKeyFor 返回某个密钥键对应的存在性标记键。
func presentExtraKeyFor(secretKey string) string {
	switch secretKey {
	case AccountLoginPasswordExtraKey:
		return AccountLoginPasswordPresentExtraKey
	case AccountLoginTOTPSecretExtraKey:
		return AccountLoginTOTPSecretPresentExtraKey
	default:
		return ""
	}
}

// IsAccountLoginSecretExtraKey 判断 extra 子键是否为账号登录密钥。
func IsAccountLoginSecretExtraKey(key string) bool {
	return key == AccountLoginPasswordExtraKey || key == AccountLoginTOTPSecretExtraKey
}

// accountLoginSecretPresent 判断值是否"存在且非零"。空串、nil 视为未配置，
// 与 dto.isCredentialValuePresent 的口径保持一致。
func accountLoginSecretPresent(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case string:
		return x != ""
	default:
		return true
	}
}

// RedactAccountLoginSecretsExtra 从 extra 副本里剥离登录密钥原文，并按存在性写入
// has_password / has_totp_secret 标记。不修改入参；返回值可安全序列化给前端。
//
// 入参为 nil 时返回 nil（避免响应里出现空对象）。
func RedactAccountLoginSecretsExtra(extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}
	out := make(map[string]any, len(extra))
	for k, v := range extra {
		// 丢弃客户端可能回传的派生标记，避免它被当成真实数据透传。
		if k == AccountLoginPasswordPresentExtraKey || k == AccountLoginTOTPSecretPresentExtraKey {
			continue
		}
		if IsAccountLoginSecretExtraKey(k) {
			continue
		}
		out[k] = v
	}
	for _, key := range AccountLoginSecretExtraKeys {
		if accountLoginSecretPresent(extra[key]) {
			out[presentExtraKeyFor(key)] = true
		}
	}
	return out
}

// MergePreservingAccountLoginSecrets 把 incoming 里的登录密钥合并到 existing 之上，语义：
//   - incoming 没提供该键：保留 existing 的值（前端全对象 PUT 时响应已脱敏，
//     不带该键，此时一次无关编辑不能把已保存的口令清空）。
//   - incoming 显式提供非空值：覆盖（管理员轮换）。
//   - incoming 显式提供空串：视为清除，删除该键而不是写入空串，
//     避免库里留下 "password": "" 这种既非"未配置"又非"已配置"的中间态。
//
// 同时剔除 has_* 派生标记。原地修改并返回 incoming（调用方已持有其所有权）。
func MergePreservingAccountLoginSecrets(existing, incoming map[string]any) map[string]any {
	if incoming == nil {
		return nil
	}
	for _, key := range accountLoginSecretPresentExtraKeys {
		delete(incoming, key)
	}
	for _, key := range AccountLoginSecretExtraKeys {
		value, provided := incoming[key]
		if !provided {
			if existingValue, ok := existing[key]; ok {
				incoming[key] = existingValue
			}
			continue
		}
		if !accountLoginSecretPresent(value) {
			delete(incoming, key)
		}
	}
	return incoming
}
