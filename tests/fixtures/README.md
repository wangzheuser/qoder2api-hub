# 离线加密夹具

此目录仅含合成数据，不含任何真实账号或本机客户端缓存。

- `credential.json`：固定 machine key、合成 JSON，经独立 `cryptography` 的 AES-128-CBC + PKCS7 生成固定密文；验证网关加密和解密的逐字节结果。
- `model-cache.json`：固定合成 uid、nonce `000102030405060708090a0b`；独立 HKDF-SHA256（salt=`qoder-model-cache-enc`，info=`model-cache-v1`，32 字节）和 AES-256-GCM（空 AAD），信封为 `QMC\x01 || nonce || ciphertext || tag`。验证解密以及错误 uid、篡改 tag 拒绝。
- AES-128/AES-256 block 期望值直接来自 FIPS-197 附录 C.1/C.3；CBC 首块来自 NIST SP800-38A。

生成时没有导入或调用待测 `qoder_sign`；`cryptography` 只用于一次性独立生成，测试运行仅依赖标准库。邻近 Qoder2Api、QoderGateway、qoder-switch、QoderTool 仓库未发现对应 `credential.json`/`model-cache.json` 官方夹具，因此这些向量验证算法与合成协议布局，不宣称验证特定官方客户端版本兼容性。

运行 `python "_test_qoder.py"` 或 `python "_test_qoder.py" --offline`：使用临时 accounts/usage、内置模型快照/文案和固定 DNS 返回；所有实际 socket 连接、UDP 发送和未 mock 的 urlopen 均阻断。默认禁止调用本机凭证扫描。`--local-credentials` 仅显式开启本机存储检查，仍禁止网络；该模式属于环境检查，不计入离线验收。
