# task26100470

保险库文档准入库：依据真实类型与调用方白名单决定是否放行待入库文件。

## 用法

```python
from vault_admission import check_admission, AdmissionDecision
from vault_admission.ooxml import DocumentType

result = check_admission(blob, frozenset({DocumentType.DOCX}))
if result.decision is AdmissionDecision.ACCEPTED:
    ...  # result.document_type 为真实类型
```

- 仅识别 DOCX / XLSX，其他内容一律拒绝；文件名与调用方声称的类型不参与判定。
- ZIP 层：仅普通单卷 Stored/Deflate，支持数据描述符（有无签名）与归档注释；拒绝加密与 ZIP64；中央目录与本地条目按 ZIP 语义交叉校验，逐条目验证展开长度与 CRC，包内不允许额外字节。
- 包层：校验 `[Content_Types].xml` 与 `_rels/.rels`，由唯一的内部 officeDocument 关系定位主文档；内容类型按 Override/Default 解析，全包恰好一个标准主文档部件，且其 XML 根元素须为对应 Transitional 命名空间的 `document` / `workbook`；参与判型的 XML 必须良构且不含 DTD/实体声明。

## 测试

```sh
python3 -m unittest discover -s tests -v
```
