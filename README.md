# GSB Bugfix Task
## 题面
密码重置令牌现在能猜、不绑用户、不过期、能重复用，改密后也不失效。reset_guard.py 是核心，tests/test_reset_guard.py 15 个红。要修成令牌随机且不可预测、绑定用户、按 TTL 过期并清理、消费一次后立即作废、改密和注销后旧令牌全部失效，短密码和常见密码要拒绝。修完 15 个测试后，还要保证 1000 组随机用户和令牌输入下没有绕过，32 线程并发消费同一令牌只能成功一次；不许改测试或硬编码令牌。边界至少覆盖空用户、ttl 为 0、过期边界、重复消费、改密后重放。

## 运行方式
```bash
python -m pytest tests -q
```

## 额外安全验证

`security_check.py` 不依赖 pytest，覆盖 1000 组随机用户/令牌输入、32 线程 × 100 轮并发消费，
以及空用户、ttl=0、过期边界、重复消费、改密/注销后重放等边界：

```bash
python3 security_check.py
```

## 安全语义

- 令牌由 `secrets.token_urlsafe(32)` 生成，长度 ≥ 43 字符，含字母与符号，不可预测、全局唯一。
- 令牌记录绑定用户、`created`/`expires` 时间戳与 `used` 标记；过期判定为 `now >= expires`，
  过期记录在创建和校验时自动清理。
- `validate_reset_token` 成功即标记已用（单次有效），`consume_reset_token` 在锁内原子消费并清除
  该用户的全部令牌；`invalidate_user_tokens` 用于注销场景。
- 密码至少 8 个字符，空白或常见密码（小写归一化后命中黑名单）拒绝，拒绝时令牌保持可重试。
- 所有共享状态访问由同一把 `RLock` 保护。

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：无外部依赖
