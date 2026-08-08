# VKIT 包格式（v1）

所有整数小端。块 = 1 MiB（默认），AES-256-GCM，12 字节 nonce + 16 字节 tag。

## 文件布局

```
偏移 0     u8[4]   magic = "VKIT"
偏移 4     u32     version = 1
偏移 8     u64     header_len
偏移 16    u64     data_len
偏移 24    u8[]    header（UTF-8 JSON，header_len 字节）
偏移 24+header_len 数据区（data_len 字节）
```

## Header JSON

```jsonc
{
  "magic": "VKIT",
  "version": 1,
  "model_id": "模型名",
  "created_at": "2026-08-08T00:00:00Z",
  "block_size": 1048576,
  "note": "买家备注（仅台账用途）",
  "recipients": [
    {
      "key_id": "sha256(spki)[:16] 的 hex",
      "algorithm": "RSA-PKCS1v1.5",
      "wrapped_cek": "base64(RSA-PKCS1v1.5(CEK))"
    }
  ],
  "files": [
    {
      "path": "model.model3.json",
      "size": 12345,
      "offset": 0,            // 该文件密文在数据区内的起始偏移
      "blocks": [
        { "i": 0, "n": "base64(nonce)", "t": "base64(tag)", "l": 1048576 }
      ]
    }
  ],
  "license": {
    "model_id": "模型ID",
    "key_id": "买家公钥指纹",
    "code_hash": "sha256(激活码) hex",
    "expires_at": "2027-12-31（可选）",
    "note": "买家备注"
  },
  "author_public_key": "base64(DER SPKI)（可选）",
  "author_signature": "base64(RSASSA-PSS-SHA256)（可选，签名 canonical_bytes）"
}
```

- CEK：32 随机字节；每个买家一个 `recipients` 条目，用买家 RSA-2048 公钥 PKCS#1 v1.5 封装。
  包内不存在任何非接收者可推导的密钥材料。
- 每块 AAD = `b"VKIT1" || file_path_utf8 || block_index_le_u64`，块间不可交换、不可跨文件移动。
- 作者签名覆盖 `canonical_bytes`（header 去掉签名字段后 sort_keys + 紧凑 JSON）。
- 路径规则：相对 POSIX 路径；禁止 `.`/`..`、`\ / : * ? " < > |`、控制字符、空组件、
  大小写不敏感重名、文件/目录前缀冲突、单组件 > 255 UTF-16、总长 > 4096 UTF-16。

## 买家请求文件（.vreq）

```jsonc
{
  "magic": "VREQ",
  "version": 1,
  "algorithm": "RSA-2048",
  "key_id": "sha256(spki)[:16] 的 hex",
  "spki": "base64(DER SubjectPublicKeyInfo)",
  "created_at": "..."
}
```
