# vaultdoc — 保险库文档准入库

依据文件真实类型与调用方白名单，决定待入库的 DOCX/XLSX 文档是否准入。
仅使用 Python 标准库，无外部依赖。

## 用法

```python
from vaultdoc import admit, DocType, Rejected

try:
    real_type = admit(data, allowed=[DocType.DOCX])  # 或 ["docx", "xlsx"]
except Rejected as exc:
    print("拒绝:", exc.reason)
```

- `data`：待检文件的完整字节内容（检查期间不会变化）。
- `allowed`：调用方白名单；识别成功但未命中白名单同样拒绝。
- 返回识别出的真实类型 `DocType.DOCX` / `DocType.XLSX`；不通过抛出 `Rejected`。

## 判定要点

- 只识别 DOCX / XLSX，文件名、扩展名、MIME、调用方声称类型均不参与判定。
- 严格校验单卷 ZIP 结构：Stored/Deflate、可选数据描述符（有无签名）与归档注释；
  拒绝加密、ZIP64、多余字节、重叠区域、名称/标志/长度/CRC 不一致。
- 依据 `[Content_Types].xml`（Override 优先，Default 按扩展名且不区分 ASCII 大小写）
  与 `_rels/.rels` 中唯一的内部 officeDocument 关系确定主文档，
  并校验其 XML 根元素命名空间；参与判型的 XML 必须良构且不含 DTD/实体声明。

## 测试

```sh
python3 -m pytest tests/ -q
```
