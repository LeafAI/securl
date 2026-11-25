package mcpserver

import (
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/audit"
)

// auditArguments deliberately enumerates safe fields of each tool. New
// fields are not automatically logged. Raw URLs, arbitrary headers, bodies,
// SQL, Redis arguments, message text and Zulip topics are never serialized.
func auditArguments(in any) map[string]any {
	m := map[string]any{}
	name := func(k, v string) {
		if v != "" {
			m[k] = clip(v, 200)
		}
	}
	target := func(raw string) {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			// Never include userinfo, query parameters or fragments.
			m["origin"] = clip(u.Scheme+"://"+u.Host, 300)
		}
	}
	arch := func(a ArcheryURL) { target(a.URL); name("site", a.Site) }
	wait := func(v *bool) {
		if v != nil {
			m["wait"] = *v
		}
	}
	sql := func(s string) { m["sql_bytes"], m["sql_sha256"] = audit.Fingerprint(s) }
	message := func(s string) { m["text_bytes"], m["text_sha256"] = audit.Fingerprint(s) }
	redis := func(c []string) {
		if len(c) > 0 {
			m["command"] = cleanCommandName(c)
			m["argument_count"] = len(c) - 1
		}
	}
	switch i := in.(type) {
	case LoginInput:
		target(i.URL)
		name("site", i.Site)
		m["force_refresh"] = i.ForceRefresh
		m["manage_credentials"] = i.ManageCredentials
		wait(i.Wait)
		m["max_block_seconds"] = i.MaxBlockSeconds
	case LoginWaitInput:
		name("login_id", i.LoginID)
		m["max_block_seconds"] = i.MaxBlockSeconds
	case LogoutInput:
		target(i.URL)
		m["all"] = i.All
		name("close_id", i.CloseID)
		m["max_block_seconds"] = i.MaxBlockSeconds
	case VaultUnlockInput:
		name("unlock_id", i.UnlockID)
		m["max_block_seconds"] = i.MaxBlockSeconds
	case RequestInput:
		target(i.URL)
		method := strings.ToUpper(i.Method)
		switch method {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
			m["method"] = method
		default:
			m["method"] = "invalid"
		}
		// The actual request event already records the upstream path. Do not
		// copy arbitrary paths on rejected calls (they can contain credentials).
		if i.Path != "" {
			m["path_bytes"], m["path_sha256"] = audit.Fingerprint(i.Path)
		}
		m["query_count"] = len(i.Query)
		m["header_count"] = len(i.Headers)
		m["form_field_count"] = len(i.Form)
		m["json_bytes"] = len(i.JSON)
		m["text_bytes"] = len(i.Text)
		m["base64_bytes"] = len(i.Base64)
		m["follow_redirects"] = i.FollowRedirects
		m["timeout_seconds"] = i.TimeoutSeconds
		m["max_response_bytes"] = i.MaxResponseBytes
	case InstancesInput:
		arch(i.ArcheryURL)
		name("instance", i.Instance)
	case GroupsInput:
		arch(i.ArcheryURL)
		name("group", i.Group)
	case QueryInput:
		arch(i.ArcheryURL)
		name("instance", i.Instance)
		name("database", i.Database)
		name("schema", i.Schema)
		m["limit"] = i.Limit
		sql(i.SQL)
	case RunSQLInput:
		arch(i.ArcheryURL)
		name("instance", i.Instance)
		name("database", i.Database)
		name("resource_group", i.ResourceGroup)
		sql(i.SQL)
		wait(i.Wait)
		if i.Backup != nil {
			m["backup"] = *i.Backup
		}
		m["max_block_seconds"] = i.MaxBlockSeconds
		m["approval_timeout_seconds"] = i.ApprovalTimeout
	case WaitInput:
		arch(i.ArcheryURL)
		m["workflow_id"] = i.WorkflowID
		m["max_block_seconds"] = i.MaxBlockSeconds
	case StatusInput:
		arch(i.ArcheryURL)
		m["workflow_id"] = i.WorkflowID
	case CancelInput:
		arch(i.ArcheryURL)
		m["workflow_id"] = i.WorkflowID
	case DBQueryInput:
		name("target", i.Target)
		name("database", i.Database)
		sql(i.SQL)
		m["limit"] = i.Limit
	case DBExecInput:
		name("target", i.Target)
		name("database", i.Database)
		sql(i.SQL)
	case RedisQueryInput:
		name("target", i.Target)
		redis(i.Command)
	case RedisExecInput:
		name("target", i.Target)
		redis(i.Command)
	case RocketMQReadInput:
		name("target", i.Target)
		name("topic", i.Topic)
		m["limit"] = i.Limit
	case TelegramSendInput:
		name("bot", i.Bot)
		name("chat", i.Chat)
		m["reply_to"] = i.ReplyTo
		message(i.Text)
	case TelegramReadInput:
		name("bot", i.Bot)
		name("chat", i.Chat)
		m["limit"] = i.Limit
		m["wait_seconds"] = i.WaitSeconds
	case DingTalkSendInput:
		name("group", i.Group)
		message(i.Text)
	case ZulipSendInput:
		name("server", i.Server)
		name("channel", i.Channel)
		message(i.Text)
	case ZulipReadInput:
		name("server", i.Server)
		name("channel", i.Channel)
		m["limit"] = i.Limit
		m["after_message_id"] = i.AfterMessageID
	}
	return m
}

func auditOutcome(out any) map[string]any {
	m := map[string]any{}
	switch o := out.(type) {
	case *LoginOutput:
		if o != nil {
			m["login_id"] = o.LoginID
			m["status"] = o.Status
			m["cached"] = o.Cached
			m["round"] = o.Round
			m["waiting_for"] = o.WaitingFor
			m["authorization_expires_at"] = o.AuthorizationExpiresAt
		}
	case LogoutOutput:
		m["status"] = o.Status
		m["removed"] = o.Removed
		m["close_id"] = o.LoginID
		m["waiting_for"] = o.WaitingFor
	case VaultUnlockOutput:
		m["status"] = o.Status
		m["unlock_id"] = o.LoginID
		m["waiting_for"] = o.WaitingFor
		m["already_unlocked"] = o.AlreadyUnlocked
	case VaultStatusOutput:
		m["state"] = o.State
		m["unlock_pending"] = o.UnlockPending
		m["failed_attempts"] = o.FailedAttempts
	case InstancesOutput:
		m["instance_count"] = len(o.Instances)
		m["database_count"] = len(o.Databases)
		if o.Pending != nil {
			m["login"] = auditOutcome(o.Pending)
		}
	case GroupsOutput:
		m["group_count"] = len(o.Groups)
		m["instance_count"] = len(o.Instances)
		if o.Pending != nil {
			m["login"] = auditOutcome(o.Pending)
		}
	case QueryOutput:
		if o.Login != nil {
			m["login"] = auditOutcome(o.Login)
		}
		if o.QueryResult != nil {
			m["row_count"] = o.RowCount
			m["truncated"] = o.Truncated
			m["cost_ms"] = o.CostMS
		}
	case CancelOutput:
		m["status"] = o.Status
	case SessionsOutput:
		m["count"] = len(o.Sessions)
	case SitesOutput:
		m["count"] = len(o.Sites)
	case DBTargetsOutput:
		m["count"] = len(o.Targets)
	case RedisTargetsOutput:
		m["count"] = len(o.Targets)
	case RocketMQTargetsOutput:
		m["count"] = len(o.Targets)
	case TelegramTargetsOutput:
		m["count"] = len(o.Bots)
	case DingTalkTargetsOutput:
		m["count"] = len(o.Groups)
	case ZulipTargetsOutput:
		m["count"] = len(o.Servers)
	case RedisQueryOutput:
		m["truncated"] = o.Truncated
		m["redactions"] = o.Redactions
	case RedisExecOutput:
		m["redactions"] = o.Redactions
		m["notified"] = o.Notified
	case RequestOutput:
		m["http_status"] = o.Status
		m["response_bytes"] = o.TotalBytes
		m["truncated"] = o.Truncated
		m["redactions"] = o.Redactions
		m["withheld"] = o.Withheld
	case ArcheryOut:
		m["phase"] = o.Phase
		m["login_id"] = o.LoginID
		m["status"] = o.Status
		m["workflow_id"] = o.WorkflowID
	case StatusOutput:
		m["status"] = o.Status
		m["workflow_id"] = o.WorkflowID
	case DBQueryOutput:
		m["row_count"] = len(o.Rows)
		m["truncated"] = o.Truncated
		m["redactions"] = o.Redactions
	case DBExecOutput:
		m["rows_affected"] = o.RowsAffected
		m["notified"] = o.Notified
	case TelegramSendOutput:
		m["sent"] = o.Sent
		m["message_id"] = o.MessageID
	case TelegramReadOutput:
		m["count"] = o.Count
		m["more"] = o.More
	case ZulipSendOutput:
		m["sent"] = o.Sent
		m["message_id"] = o.MessageID
	case ZulipReadOutput:
		m["count"] = o.Count
		m["more"] = o.More
	case DingTalkSendOutput:
		m["sent"] = o.Sent
	case RocketMQReadOutput:
		m["count"] = o.Count
		m["queues"] = o.Queues
		m["truncated"] = o.Truncated
	}
	return m
}
