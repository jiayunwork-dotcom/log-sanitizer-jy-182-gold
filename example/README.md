# log-sanitizer 示例

本目录提供一份含敏感信息的样例日志 `sample.log`，可直接用来试跑脱敏工具。

## 试跑（输出到终端）

```bash
go run . -in example/sample.log
```

输出会用 `*` 遮盖邮箱、手机号、身份证、IPv4：

```
... user a***@example.com logged in from 192.168.*.*
... failed SMS to 138****5678, retry scheduled
... payment for id 110101********1234 rejected by gateway
... webhook delivered to 10.0.0.*.* status=200
... request from 139****1111 attached to order ORD-7781
extra line with irregular spacing and trailing garbage
```

## 只脱敏部分字段

```bash
go run . -in example/sample.log -mask phone,ip
```

## 关闭格式标准化（保留原始空白）

```bash
go run . -in example/sample.log -normalize=false
```

## 批处理整个目录，输出到另一个目录

```bash
go run . -in example/ -out out/
# 生成 out/sample.log.sanitized
```

> 默认对每行做空白折叠与裁剪；`mask` 默认开启全部四种脱敏。
> 若只想要纯格式标准化（不脱敏），传 `-mask ""` 即可。
