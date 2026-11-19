# 回调 state 防线修复交付文档

## 1. 问题与根因

统一认证门户的 CSRF 防线依赖 OAuth `state` 参数：发起阶段（`BeginAuth`）生成
state 写入会话并随授权 URL 发给外部提供商，回调阶段（`CompleteUserAuth` →
`validateState`）比对回调请求携带的 state 与会话中保存的原始 state。

安全测试发现：**构造缺失 state 参数的回调请求可以静默通过并完成登录，只有携带
错误 state 的对照组被拒绝。**

定位到两层根因：

1. **回调比对被空值短路（主根因，`gothic/gothic.go` 的 `validateState`）**
   原实现为：

   ```go
   originalState := authURL.Query().Get("state")
   if originalState != "" && (originalState != reqState) {
       return errors.New("state token mismatch")
   }
   ```

   只有当会话中的 `originalState` 非空时才执行比对。一旦会话里没有 state，
   整个校验被跳过并返回 `nil`，回调静默放行。

2. **四家提供商发起阶段不回传 state（触发根因）**
   `steam`、`xero`、`twitter`、`twitterv2` 的 `BeginAuth(state string)` 均接收
   state 却完全不使用，生成的授权 URL 中不含 state。经这些提供商发起的登录，
   会话 `AuthURL` 里 `originalState` 恒为空，稳定命中上面的短路分支，防线形同
   虚设。审计回读核验看到的“缺 state 登录成功”记录即由此产生。

此外，网关对超时回调自动重发，放大了缺失 state 请求的危害：重发请求同样不带
state，旧逻辑下每一次重发都能静默完成登录。

## 2. 修复方案

### 2.1 回调防线：state 强制双向非空且逐提供方比对（`gothic/gothic.go`）

`validateState` 改为三段式判定，任一不过即返回 error，由 `CompleteUserAuth`
沿既有错误返回路径原样上抛（函数签名与调用方式未变，错误不静默吞掉）：

| 判定顺序 | 条件 | 返回错误 | 含义 |
| --- | --- | --- | --- |
| 1 | 会话 AuthURL 中 `originalState == ""` | `state token is missing in the authorization session` | 会话侧无 state（含不经发起流程直接装载会话值的存量形态），无可比对基准 |
| 2 | 回调请求 `reqState == ""` | `state token is missing from the callback request` | 回调缺 state 参数与带空 state（`state=`）两种形态统一走此口径 |
| 3 | `originalState != reqState` | `state token mismatch` | 错误 state，保持既有错误文案与拒绝行为不变 |
| — | 全部通过 | `nil` | 正常登录流程行为不变 |

### 2.2 state 缺失/空 state 的拒绝口径与报错形态设计理由

- **缺 state 与空 state 同口径拒绝。** `url.Values.Get` 对“参数不存在”和
  “参数存在但值为空”都返回空字符串，二者在密码学意义上等价：都无法证明回调
  与某次发起绑定。若区别对待（例如空值放行、缺失拒绝），攻击者只需把无 state
  请求改写成 `state=` 即可绕过，因此两者必须落到同一拒绝分支、同一错误文案。
- **会话侧缺失与请求侧缺失使用不同错误文案。** 两类缺陷的责任面不同：会话侧
  缺 state 意味着系统自身没有建立 CSRF 基准（提供商发起缺陷或存量会话），
  请求侧缺 state 意味着回调消息不完整（网关重发丢参/提供商未回传/构造攻击）。
  区分文案便于审计侧按错误码聚类定位，但两者都返回非空 error、都拒绝登录，
  不存在静默放行。
- **错误沿用既有 `errors.New` 形态与既有返回路径。** 不引入新的 error 类型、
  不改变 HTTP 状态码处理（`BeginAuthHandler` 等上层对任何 error 仍写
  `400 Bad Request`），错误经 `CompleteUserAuth` 的返回值上抛，与原
  `state token mismatch` 的上报方式完全一致，适配既有错误监控与审计回读。
- **错误 state 文案保持 `state token mismatch` 不变**，对照组行为零变化。

### 2.3 跨提供方 state 不互认的保证

会话按提供方名分键存储（`StoreInSession(providerName, ...)`），回调时
`GetFromSession(providerName, req)` 只取出当前提供方的会话，`validateState`
比对的 state 全部来自该提供方自己的 `AuthURL`。整个比对过程不读取、不接受任何
其它提供方的 state，因此多提供方会话并存时，A 提供方发起的 state 永远不可能
通过 B 提供方回调的校验。新增 `Test_StateValidation_ProviderIsolation` 用例
固化该边界。

### 2.4 四家提供商发起阶段回传 state

| 提供商 | 协议 | 修复手法 |
| --- | --- | --- |
| steam | OpenID 2.0 | `getAuthURL` 增加 state 入参，在登录 URL 查询参数中追加 `state` |
| xero | OAuth 1.0 | 新增包内 `withState`，在 consumer 返回的授权 URL 上解析并追加 `state` 查询参数，保留原有 `oauth_token` 等参数 |
| twitter | OAuth 1.0 | 同上（authorize / authenticate 两个入口均生效，因为共用 `BeginAuth`） |
| twitterv2 | OAuth 1.0 | 同上 |

三家 OAuth1 提供商的协议本身没有原生 state 字段，采用在授权 URL 查询串附加
`state` 的方式：提供方授权完成后会把该查询参数原样带回回调 URL，
`gothic.GetState` 即可在回调侧取回并完成比对。`withState` 在 URL 解析失败时
原样返回入参 URL，不破坏既有降级行为。

## 3. 改动面逐文件登记

| 文件 | 改动内容 | 对应题面要求 |
| --- | --- | --- |
| `gothic/gothic.go` | 重写 `validateState`：删除 `originalState != ""` 短路；新增会话侧缺 state、请求侧缺/空 state 两个拒绝分支；保留 mismatch 分支；补充说明注释 | 缺失 state 不得静默放行；缺/空 state 同口径拒绝；错误沿既有路径上报不吞掉；跨提供方不互认；错误 state 行为不变 |
| `providers/steam/steam.go` | `BeginAuth`/`getAuthURL` 透传 state 并写入授权 URL 查询参数 | steam 发起阶段必须回传 state |
| `providers/xero/xero.go` | `BeginAuth` 用新增 `withState` 把 state 附加到授权 URL；新增 `net/url` 导入；更新注释 | xero 发起阶段必须回传 state |
| `providers/twitter/twitter.go` | 同上；新增 `net/url` 导入；更新注释 | twitter 发起阶段必须回传 state |
| `providers/twitterv2/twitterv2.go` | 同上；新增 `net/url` 导入；更新注释 | twitterv2 发起阶段必须回传 state |
| `gothic/gothic_test.go` | 新增 5 个 state 断言用例（见 §5）；4 个既有用例的存量会话夹具补 state（见 §4） | 三类断言用例；存量形态处置；既有测试保持通过 |
| `providers/steam/steam_test.go` | `Test_BeginAuth` 增加授权 URL 含 `state=test_state` 的断言；新增 `net/url` 导入 | steam 发起回传 state 行为断言 |
| `providers/xero/xero_test.go` | `Test_BeginAuth` 增加 state 与 oauth_token 共存断言；新增 `net/url` 导入 | xero 发起回传 state 行为断言 |
| `providers/twitter/twitter_test.go` | authorize/authenticate 两个分支均增加 state 断言；新增 `net/url` 导入 | twitter 发起回传 state 行为断言 |
| `providers/twitterv2/twitterv2_test.go` | 同上 | twitterv2 发起回传 state 行为断言 |
| `cmd/stateboundary/main.go` | 新增独立构造实测程序，按四类回调形态边界输入表逐类驱动 `CompleteUserAuth` 并打印实测读数 | 构造实测留痕与可复跑 |

## 4. 存量形态（不经发起流程直接装载会话值）的处置

题面要求覆盖的存量形态指：应用代码直接向 session 写入一个未经 `BeginAuth`
产生的会话值，其 `AuthURL` 中没有 state。

**处置方式：拒绝。** 新 `validateState` 的第 1 判定分支即为此而设——会话侧
`originalState` 为空时返回 `state token is missing in the authorization
session`，登录不完成、错误上抛。理由是：没有 CSRF 基准的会话无法证明回调来源
合法，继续放行等于保留原漏洞；滚动升级期内这类旧会话应被拒绝并要求重新发起
登录，而不是兼容放行。

测试侧影响与处理：`gothic/gothic_test.go` 中 `Test_CompleteUserAuth`、
`Test_CompleteUserAuthWithSessionDeducedProvider`、
`Test_CompleteUserAuthWithContextParamProvider`、`Test_Logout` 四个既有用例
原来直接装载无 state 的 `faux.Session` 夹具，修复后按新安全口径必然被拒绝。
这些用例的测试意图是验证“提供方名解析 / 会话装载 / Logout 清理”等流程而非
state 行为，因此将夹具更新为修复后唯一合法的存量形态——会话 `AuthURL` 携带
state、回调请求携带匹配 state（均为 `test_state`），用例断言意图与数量保持
不变。另新增 `Test_StateValidation_MissingStateInSessionRejected` 专门固化
“无 state 存量会话必须拒绝”的口径。

## 5. 新增/更新测试用例清单

落位均与既有 state 校验用例同文件（`gothic/gothic_test.go`）、同框架
（testify/assert + httptest + 既有 ProviderStore）：

| 用例名 | 断言内容 |
| --- | --- |
| `Test_StateValidation_MissingStateRejected` | 回调完全不带 state 参数 → 返回含 "state" 的非空 error，不完成登录 |
| `Test_StateValidation_EmptyStateRejected` | 回调带 `state=` 空值 → 同上，与缺失同口径 |
| `Test_StateValidation_ValidStatePasses` | 回调 state 与会话一致 → 无 error、返回非空用户，正常流程不变 |
| `Test_StateValidation_MissingStateInSessionRejected` | 存量无 state 会话 → 拒绝；补齐存量形态处置面 |
| `Test_StateValidation_ProviderIsolation` | 用其它提供方的 state 打当前提供方回调 → `state token mismatch`；本提供方正确 state 仍通过 |

既有的 `Test_StateValidation`（正确 state 通过 + 错误 state 拒绝）原样保留并
继续通过，错误 state 拒绝行为不变。

四家提供商发起回传 state 的断言均落在各家既有 `Test_BeginAuth` 内，同文件同
框架，解析 `AuthURL` 查询串断言 `state` 参数值，并验证未破坏原有参数
（如 `oauth_token`）。

## 6. 验收命令与实测读数

### 6.1 验收命令最终读数（修复后）

命令：

```
go test -count=1 ./gothic/... ./providers/steam/... ./providers/xero/... ./providers/twitter/... ./providers/twitterv2/...
```

读数：

```
ok  	github.com/markbates/goth/gothic         	1.219s
ok  	github.com/markbates/goth/providers/steam	1.114s
ok  	github.com/markbates/goth/providers/xero 	1.629s
ok  	github.com/markbates/goth/providers/twitter	1.654s
ok  	github.com/markbates/goth/providers/twitterv2	1.622s
```

零失败。另执行 `go test -count=1 ./...` 全仓 74 个含测试包全部 `ok`，
`go vet ./...` 退出码 0。

### 6.2 四类回调形态边界输入表构造实测

复跑方式：`go run ./cmd/stateboundary`

统一前置：会话由发起流程等价形态装载，`AuthURL` 中原始 state 为
`state_REAL`。

| # | 形态 | 构造的回调 URL | 期望 | 实测 error 读数 | 结论 |
| --- | --- | --- | --- | --- | --- |
| 1 | 缺 state | `/auth/callback?provider=faux` | 拒绝 | `state token is missing from the callback request` | 拒绝，未静默放行 |
| 2 | 空 state | `/auth/callback?provider=faux&state=` | 拒绝（与 #1 同口径） | `state token is missing from the callback request` | 拒绝，同口径同文案 |
| 3 | 错误 state | `/auth/callback?provider=faux&state=state_FAKE` | 拒绝（既有行为不变） | `state token mismatch` | 拒绝，文案与旧实现一致 |
| 4 | 正常 state | `/auth/callback?provider=faux&state=state_REAL` | 放行（既有行为不变） | `<nil>`（登录完成） | 通过 |

程序末行输出：`RESULT: PASS (missing/empty/wrong rejected, normal accepted)`，
退出码 0。

### 6.3 修复前对照（基线）

修复前同一验收命令五个包均 `ok`（缺陷被旧短路逻辑掩盖，无测试覆盖缺失
state），而按 §6.2 表手工构造的缺 state 回调在旧 `validateState` 下返回
`nil` 并静默完成登录——即安全团队观测到的现象。修复后该输入稳定返回
`state token is missing from the callback request`。

## 7. 题面要求逐条落点对照

| 题面要求 | 落点 |
| --- | --- |
| 定位根因并修复 | §1 两层根因；§2.1 + §2.4 修复 |
| 缺失 state 的回调不得静默放行 | `validateState` 第 2 分支 + `Test_StateValidation_MissingStateRejected` |
| 四家提供商发起阶段必须回传 state 使比对可执行 | §2.4 四个 provider 改动 + 各自 `Test_BeginAuth` 断言 |
| 既有正常登录流程不变 | 第 4 分支 `nil` 路径未改；`Test_StateValidation_ValidStatePasses`、既有 `Test_StateValidation` 通过 |
| 错误 state 拒绝行为不变 | `state token mismatch` 文案与分支保留；构造实测 #3 读数一致 |
| 缺 state 与空 state 两种形态拒绝口径 | 同一分支同一文案，§2.2 说明理由，实测 #1/#2 读数相同 |
| 错误沿既有错误返回路径上报、不静默吞掉 | 沿用 `errors.New` + `CompleteUserAuth` 返回值上抛，无新增吞错点 |
| 不经发起流程直接装载会话值的存量形态处置 | §4：拒绝（第 1 分支）+ 专项用例 + 既有夹具迁移说明 |
| 拒绝口径与报错形态自行设计并写明理由 | §2.2 |
| 多提供方会话并存时跨提供方 state 不互认 | §2.3 机制说明 + `Test_StateValidation_ProviderIsolation` |
| 改动面逐文件登记、每条要求落到对应改动 | §3 |
| 验收最终读数与构造实测读数入文档 | §6.1、§6.2 |
| 三类断言用例落位 gothic 既有 state 用例同文件同框架 | §5，`gothic/gothic_test.go` |
| 四家发起回传 state 断言落位各家既有发起用例同文件同框架 | §3、§5，四个 `*_test.go` 的 `Test_BeginAuth` |
| 既有测试保持通过、验收命令零失败 | §6.1，五包 ok；全仓 74 包 ok |
| 改动区域为 gothic 包回调处理入口 | 核心防线改动集中在 `gothic/gothic.go` 的 `CompleteUserAuth` 调用链上的 `validateState` |
