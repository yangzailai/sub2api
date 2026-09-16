//go:build unit

package service

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsAccountLoginSecretExtraKey(t *testing.T) {
	require.True(t, IsAccountLoginSecretExtraKey("password"))
	require.True(t, IsAccountLoginSecretExtraKey("totp_secret"))
	require.False(t, IsAccountLoginSecretExtraKey("has_password"))
	require.False(t, IsAccountLoginSecretExtraKey("email"))
	require.False(t, IsAccountLoginSecretExtraKey(""))
}

func TestRedactAccountLoginSecretsExtra_StripsPlaintextAndEmitsFlags(t *testing.T) {
	extra := map[string]any{
		"email":                  "user@example.com",
		"source":                 "codex-sms-auth",
		"codex_fingerprint_mode": "session",
		"password":               "MyP@ssw0rd",
		"totp_secret":            "JBSWY3DPEHPK3PXP",
	}

	out := RedactAccountLoginSecretsExtra(extra)

	require.NotContains(t, out, "password")
	require.NotContains(t, out, "totp_secret")
	require.True(t, out["has_password"].(bool))
	require.True(t, out["has_totp_secret"].(bool))
	// 非密钥字段原样保留
	require.Equal(t, "user@example.com", out["email"])
	require.Equal(t, "codex-sms-auth", out["source"])
	require.Equal(t, "session", out["codex_fingerprint_mode"])

	// 入参不得被修改
	require.Equal(t, "MyP@ssw0rd", extra["password"])
	require.Equal(t, "JBSWY3DPEHPK3PXP", extra["totp_secret"])
}

func TestRedactAccountLoginSecretsExtra_NoFlagWhenAbsentOrEmpty(t *testing.T) {
	absent := RedactAccountLoginSecretsExtra(map[string]any{"email": "a@b.c"})
	require.NotContains(t, absent, "has_password")
	require.NotContains(t, absent, "has_totp_secret")

	// 空串视为未配置，不产出标记
	empty := RedactAccountLoginSecretsExtra(map[string]any{"password": "", "totp_secret": ""})
	require.NotContains(t, empty, "has_password")
	require.NotContains(t, empty, "has_totp_secret")

	require.Nil(t, RedactAccountLoginSecretsExtra(nil))
}

func TestRedactAccountLoginSecretsExtra_DropsClientSuppliedFlags(t *testing.T) {
	// 前端可能把上一轮响应里的 has_* 原样带回；它们不是真实数据，必须丢弃后重新派生。
	out := RedactAccountLoginSecretsExtra(map[string]any{
		"has_password":    true,
		"has_totp_secret": true,
	})
	require.NotContains(t, out, "has_password", "无真实密钥时不应保留客户端伪造的标记")
	require.NotContains(t, out, "has_totp_secret")
}

// 前端全对象 PUT 且响应已脱敏：incoming 不带这两个键，必须保留旧值，
// 否则一次无关编辑（例如只改并发数）就会清空已保存的口令与 2FA 种子。
func TestMergePreservingAccountLoginSecrets_PreservesWhenIncomingMissing(t *testing.T) {
	existing := map[string]any{
		"password":    "MyP@ssw0rd",
		"totp_secret": "JBSWY3DPEHPK3PXP",
		"email":       "user@example.com",
	}
	incoming := map[string]any{
		"codex_fingerprint_mode": "session",
	}

	out := MergePreservingAccountLoginSecrets(existing, incoming)

	require.Equal(t, "MyP@ssw0rd", out["password"])
	require.Equal(t, "JBSWY3DPEHPK3PXP", out["totp_secret"])
	require.Equal(t, "session", out["codex_fingerprint_mode"])
	// 非密钥字段仍由 incoming 决定（email 未提交 = 删除），本函数不干预。
	require.NotContains(t, out, "email")
}

func TestMergePreservingAccountLoginSecrets_RotatesWhenProvided(t *testing.T) {
	existing := map[string]any{"password": "old", "totp_secret": "OLDSECRET"}
	incoming := map[string]any{"password": "new", "totp_secret": "NEWSECRET"}

	out := MergePreservingAccountLoginSecrets(existing, incoming)

	require.Equal(t, "new", out["password"])
	require.Equal(t, "NEWSECRET", out["totp_secret"])
}

func TestMergePreservingAccountLoginSecrets_EmptyStringClearsKey(t *testing.T) {
	existing := map[string]any{"password": "old", "totp_secret": "OLDSECRET"}
	incoming := map[string]any{"password": "", "totp_secret": ""}

	out := MergePreservingAccountLoginSecrets(existing, incoming)

	// 清除应删键，而不是写入空串——否则库里留下既非"未配置"又非"已配置"的中间态
	require.NotContains(t, out, "password")
	require.NotContains(t, out, "totp_secret")
}

func TestMergePreservingAccountLoginSecrets_StripsDerivedFlags(t *testing.T) {
	existing := map[string]any{"password": "old"}
	incoming := map[string]any{"has_password": true, "has_totp_secret": false}

	out := MergePreservingAccountLoginSecrets(existing, incoming)

	require.NotContains(t, out, "has_password", "派生标记不允许落库")
	require.NotContains(t, out, "has_totp_secret")
	require.Equal(t, "old", out["password"], "剔除标记后仍应回填旧口令")
}

func TestMergePreservingAccountLoginSecrets_NilInputs(t *testing.T) {
	require.Nil(t, MergePreservingAccountLoginSecrets(map[string]any{"password": "x"}, nil))

	// existing 为 nil 时不应 panic，也不应凭空造出键
	out := MergePreservingAccountLoginSecrets(nil, map[string]any{"email": "a@b.c"})
	require.Equal(t, "a@b.c", out["email"])
	require.NotContains(t, out, "password")
	require.NotContains(t, out, "totp_secret")
}
