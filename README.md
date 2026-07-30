# checkpoint-mcp

MCP server for **Check Point Harmony Endpoint** (endpoint protection/EDR,
part of Check Point's Infinity Portal). Exposes the Harmony Endpoint Web
Management API's policy, asset, vulnerability posture, quarantine, and
remediation methods as MCP tools.

> Naming note: MSPbots' own integration is registered as "Check Point
> Harmony Endpoint" (`subjectCode=CHECKPOINT`). This MCP covers exactly the
> 11 methods MSPbots itself has configured.

## Overview

- Stateless HTTP service. No credentials are ever persisted — each request
  supplies its own Infinity Portal API key via headers, used only for the
  lifetime of that single request.
- Supports concurrent requests; per-request credential isolation is done via
  Python `contextvars`, not a global/shared client instance.
- Entry points: `POST /mcp` (MCP protocol) and `GET /health` (health check).
- Default port: `8080` (configurable via `MCP_HTTP_PORT`).

## Authentication

Check Point's Infinity Portal uses a 2-step API-key exchange, and the
Harmony Endpoint Web Management API on top of that requires **both**
resulting tokens together on every real call:

1. `POST {region}/auth/external` with `{clientId, accessKey}` → a portal
   bearer token (`data.token`), valid ~30 minutes.
2. `POST {region}/app/endpoint-web-mgmt/harmony/endpoint/api/v1/session/login/cloud`
   with `Authorization: Bearer <portal token>` → a management-service
   `apiToken`, valid only **~6 minutes**.
3. Every real endpoint call requires **both** `Authorization: Bearer
   <portal token>` **and** `x-mgmt-api-token: <apiToken>` headers together,
   plus `x-mgmt-run-as-job: on`.

Because the `apiToken` is short-lived anyway, this server performs this
entire 2-step login fresh on **every single tool call** — nothing is
cached or persisted across MCP requests.

**All 11 methods are asynchronous jobs.** The initial call only returns
`{"jobId": ...}`; the real result is fetched by polling `GET
.../jobs/{jobId}` until the job leaves an in-progress state (this server
polls every 1s, up to a 30s timeout, per tool call).

### HEADER 授权参数说明

| Header | 类型 | 是否必填 | 默认值 | 枚举值 | 字段描述 | Example |
|---|---|---|---|---|---|---|
| `X-CheckPoint-Client-Id` | string | 是 | 无 | 无 | Infinity Portal API Key 的 Client ID | `45217fa1-6c33-4389-a169-909fa72e99dd` |
| `X-CheckPoint-Access-Key` | string | 是 | 无 | 无 | Infinity Portal API Key 的 Secret/Access Key | `911b25e9-149a-45b3-a9a7-a9d43be24635` |
| `X-CheckPoint-Region` | string | 是 | 无 | `https://cloudinfra-gw-us.portal.checkpoint.com`（US）、`https://cloudinfra-gw.portal.checkpoint.com`（EU）、`https://cloudinfra-gw.ap.portal.checkpoint.com`（AP） | 租户所在数据驻留区域的网关地址，与 MSPbots 集成配置里的 Region 下拉选项一致 | `https://cloudinfra-gw.ap.portal.checkpoint.com` |

Missing any header returns `401`:
```json
{
  "error": "Missing credentials",
  "message": "This server requires the X-CheckPoint-Client-Id, X-CheckPoint-Access-Key, and X-CheckPoint-Region headers",
  "required_headers": ["X-CheckPoint-Client-Id", "X-CheckPoint-Access-Key", "X-CheckPoint-Region"],
  "optional_headers": []
}
```

## Environment Variables

| Variable | 类型 | 是否必填 | 默认值 | 说明 |
|---|---|---|---|---|
| `MCP_HTTP_PORT` | int | 否 | `8080` | HTTP 监听端口 |
| `MCP_HTTP_HOST` | string | 否 | `0.0.0.0` | HTTP 监听地址 |

## MCP Endpoint

- `POST /mcp` — MCP protocol (streamable HTTP transport)
- `GET /health` — health check, returns `{"status": "ok", "service": "checkpoint-mcp", "transport": "http"}`

## Tool List

| Tool | 功能 | 参数 |
|---|---|---|
| `checkpoint_get_policy_metadata` | 列出所有 Harmony Endpoint 策略规则的元数据 | 无 |
| `checkpoint_get_policy_modifications` | 获取指定策略规则的修改历史 | `rule_id`（必填） |
| `checkpoint_get_policy_assignments` | 获取指定策略规则的分配对象 | `rule_id`（必填） |
| `checkpoint_get_computers_filtered` | 列出受管计算机/端点（可选过滤条件） | `filter`（可选，vendor 自定义过滤对象） |
| `checkpoint_search_organization_tree` | 搜索组织架构树（组/用户/计算机） | `search_term`、`search_type`、`entity_types`、`offset`、`page_size`（均可选） |
| `checkpoint_get_vulnerability_data` | 列出组织级漏洞态势数据 | `offset`、`page_size`（均可选） |
| `checkpoint_get_vulnerability_devices` | 获取指定设备的漏洞态势详情 | `device_ids`（必填），`offset`、`page_size`（可选） |
| `checkpoint_get_vulnerability_scan_status` | 获取漏洞扫描状态 | 无 |
| `checkpoint_get_quarantine_files` | 列出隔离区文件 | `offset`、`page_size`（均可选） |
| `checkpoint_get_remediation_status` | 列出修复/响应操作的状态 | 无 |
| `checkpoint_get_remediation_results_slim` | 获取指定修复操作的简要结果 | `remediation_id`（必填），`offset`、`page_size`（可选） |

Responses are the vendor's job-result JSON, pretty-printed
(`{"status": "DONE", "statusCode": ..., "data": ...}`), returned as-is.

## 测试示例

```bash
# Health check
curl -s http://localhost:8080/health

# Call a tool via the MCP protocol (streamable HTTP) — requires an
# initialize handshake first per the MCP spec; abbreviated example below
# shows the tool-call request body only:
curl -s -X POST http://localhost:8080/mcp \
  -H "X-CheckPoint-Client-Id: <your-client-id>" \
  -H "X-CheckPoint-Access-Key: <your-access-key>" \
  -H "X-CheckPoint-Region: https://cloudinfra-gw.ap.portal.checkpoint.com" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: <session-id-from-initialize>" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "checkpoint_get_policy_metadata",
      "arguments": {}
    }
  }'
```

**Live-verified** (2026-07-30) against a real Harmony Endpoint tenant, all
11 tools called end-to-end through this running server: `..._policy_metadata`
returned real policy rules (e.g. "Testing App Control", several
organization-default rules across the Access/Threat Prevention/Data
Protection/OneCheck/General Settings/Deployment/Agent Settings/Data Loss
Prevention families); `..._policy_assignments` returned the real
"Entire Organization" assignment for a default rule; `..._computers_filtered`
returned 18 real managed computers with live agent health data;
`..._search_organization_tree` returned real groups (Virtual Directory
Structure, ChromeOsDesktops, etc.); `..._vulnerability_scan_status`
returned real per-device scan statuses; `..._remediation_status` returned
a real completed `DA_COLLECT_LOGS` remediation action;
`..._remediation_results_slim` (using that action's real ID) returned its
real per-machine result; `..._quarantine_files` returned a real quarantined
file record; `..._vulnerability_data` and `..._vulnerability_devices`
returned valid empty result sets (no vulnerability data present for this
tenant at test time — a legitimate empty response, not an error);
`..._policy_modifications` (using a real rule ID) returned `statusCode
204` (no modification history for that rule — also a legitimate response).

## API Reference

- Auth flow discovered and confirmed via the third-party Shuffle SOAR
  platform's public integration docs (Check Point does not appear to
  publish this specific 2-step token exchange in an easily discoverable
  public reference of their own):
  https://shuffler.io/apps/Harmony_Endpoint_Management/integrations/Checkpoint
- No further official public API reference for the Harmony Endpoint Web
  Management API's individual method schemas was found; behavior for each
  of the 11 methods in this README was determined via MSPbots' own stored
  `apiConfig` (path/params) cross-checked against live calls with real
  credentials (see Live-verified above), following this program's
  standing rule to never trust stored config as ground truth without
  confirming against the real API.

## Known Gaps

- **Scope is exactly MSPbots' 11 configured endpoints, not the vendor's
  full API surface** — Harmony Endpoint Web Management exposes many more
  categories (Session, Jobs, Indicators of Compromise, Remediation &
  Response - Agent/Threat Prevention, etc. per the Shuffle integration's
  own category list) that MSPbots does not use; those are out of scope
  here.
- **`checkpoint_get_computers_filtered`'s `filter` parameter shape is
  undocumented** — MSPbots' own stored config sends an empty body, so this
  server accepts an optional generic `dict` and defaults to `{}` (an
  unfiltered listing) rather than guessing at a specific filter schema.
- **Async job polling timeout is fixed at 30s (1s interval)** — all live
  test calls completed in well under a second, but a tenant with a very
  large dataset could plausibly exceed this; not configurable via env var
  in this version.
- **Job responses can validly be non-200/204 without being an error** —
  e.g. `checkpoint_get_policy_modifications` returned `statusCode: 204`
  or `checkpoint_get_vulnerability_data` returned an empty `data` array;
  this server surfaces the job result as-is rather than treating anything
  other than 200 as a tool-level error, since the async job framing means
  the vendor's own success/failure signaling lives inside the JSON body,
  not the outer HTTP status code.
