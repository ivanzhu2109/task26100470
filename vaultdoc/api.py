"""对外准入接口。"""
from __future__ import annotations

from collections.abc import Collection

from .errors import Rejected
from .opc import DocType, detect_type
from .zipcheck import parse_zip


def admit(data: bytes, allowed: Collection[DocType | str]) -> DocType:
    """校验字节流并依据调用方白名单决定是否准入。

    - ``data``: 待检文件的完整字节内容（检查期间不会变化）。
    - ``allowed``: 调用方白名单，元素为 DocType 或其值字符串（如 "docx"）。

    返回识别出的真实类型；不通过时抛出 Rejected。
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise Rejected("输入必须是字节内容")
    whitelist: set[DocType] = set()
    for item in allowed:
        try:
            whitelist.add(item if isinstance(item, DocType) else DocType(str(item)))
        except ValueError as exc:
            raise Rejected(f"白名单包含未知类型: {item!r}") from exc
    detected = detect_type(parse_zip(bytes(data)))
    if detected not in whitelist:
        raise Rejected(f"真实类型 {detected.value} 不在调用方白名单内")
    return detected
