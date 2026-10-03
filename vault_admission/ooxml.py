"""OOXML 包结构校验与真实类型判定。"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from enum import Enum
from typing import Dict, Tuple

from .zip_reader import ZipEntry, validate_entry_name


class DocumentType(Enum):
    """可识别的真实文档类型。"""

    DOCX = "docx"
    XLSX = "xlsx"


class PackageError(ValueError):
    """OOXML 包结构不符合准入要求。"""


_NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
_NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_REL_OFFICE_DOCUMENT = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)

_MAIN_CONTENT_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml":
        DocumentType.DOCX,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml":
        DocumentType.XLSX,
}

_MAIN_ROOTS = {
    DocumentType.DOCX:
        "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}document",
    DocumentType.XLSX:
        "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}workbook",
}

_HEX = frozenset("0123456789abcdefABCDEF")


def _fail(message: str) -> None:
    raise PackageError(message)


def _ascii_lower(text: str) -> str:
    return "".join(chr(ord(ch) + 32) if "A" <= ch <= "Z" else ch for ch in text)


def _percent_decode(raw: str) -> str:
    """按 UTF-8 进行一次百分号解码，拒绝损坏的转义。"""
    buf = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "%":
            if i + 2 >= len(raw) or raw[i + 1] not in _HEX or raw[i + 2] not in _HEX:
                _fail("百分号转义损坏")
            buf.append(int(raw[i + 1:i + 3], 16))
            i += 3
        else:
            buf.extend(ch.encode("utf-8"))
            i += 1
    try:
        return bytes(buf).decode("utf-8")
    except UnicodeDecodeError:
        _fail("百分号解码结果不是有效 UTF-8")


def _normalize_part_name(raw: str) -> str:
    """规范化主文档目标与 Override 部件名。"""
    decoded = _percent_decode(raw)
    if "?" in decoded or "#" in decoded:
        _fail("部件名含查询串或片段")
    if decoded.startswith("/"):
        decoded = decoded[1:]
    if decoded.endswith("/") or not decoded:
        _fail("部件名不能为空或是目录")
    validate_entry_name(decoded)
    return decoded


def _parse_xml(data: bytes, what: str) -> ET.Element:
    """解析参与判型的 XML：必须完整、良构，拒绝 DTD 与实体声明。"""
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        _fail(f"{what} 含 DTD 或实体声明")
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        _fail(f"{what} 不是良构 XML")


def _parse_content_types(root: ET.Element) -> Tuple[Dict[str, str], Dict[str, str]]:
    if root.tag != f"{{{_NS_CT}}}Types":
        _fail("[Content_Types].xml 根元素不是 Types")
    defaults: Dict[str, str] = {}
    overrides: Dict[str, str] = {}
    for child in root:
        if child.tag == f"{{{_NS_CT}}}Default":
            ext = child.get("Extension")
            content_type = child.get("ContentType")
            if not ext or not content_type:
                _fail("Default 缺少 Extension 或 ContentType")
            key = _ascii_lower(ext)
            if key in defaults:
                _fail("规范化后重复的 Default 扩展名声明")
            defaults[key] = content_type
        elif child.tag == f"{{{_NS_CT}}}Override":
            part = child.get("PartName")
            content_type = child.get("ContentType")
            if not part or not content_type:
                _fail("Override 缺少 PartName 或 ContentType")
            key = _normalize_part_name(part)
            if key in overrides:
                _fail("规范化后重复的 Override 部件声明")
            overrides[key] = content_type
        else:
            _fail("[Content_Types].xml 含无法识别的元素")
    return defaults, overrides


def _parse_root_rels(root: ET.Element) -> str:
    if root.tag != f"{{{_NS_REL}}}Relationships":
        _fail("_rels/.rels 根元素不是 Relationships")
    targets = []
    for child in root:
        if child.tag != f"{{{_NS_REL}}}Relationship":
            _fail("_rels/.rels 含无法识别的元素")
        if child.get("Type") != _REL_OFFICE_DOCUMENT:
            continue
        mode = child.get("TargetMode")
        if mode is not None and mode != "Internal":
            _fail("主文档关系必须是内部关系")
        target = child.get("Target")
        if not target:
            _fail("主文档关系缺少 Target")
        targets.append(target)
    if len(targets) != 1:
        _fail("根关系中必须恰好有一个 officeDocument 关系")
    return targets[0]


def _content_type_of(name: str, defaults: Dict[str, str],
                     overrides: Dict[str, str]) -> str:
    if name in overrides:
        return overrides[name]
    segment = name.rsplit("/", 1)[-1]
    if "." in segment:
        return defaults.get(_ascii_lower(segment.rsplit(".", 1)[1]))
    return None


def detect_document_type(entries: Dict[str, ZipEntry]) -> DocumentType:
    """依据完整包结构判定真实类型，与文件名和调用方声称无关。"""
    ct_entry = entries.get("[Content_Types].xml")
    rels_entry = entries.get("_rels/.rels")
    if ct_entry is None or rels_entry is None:
        _fail("缺少 [Content_Types].xml 或 _rels/.rels")

    defaults, overrides = _parse_content_types(
        _parse_xml(ct_entry.data, "[Content_Types].xml"))
    target = _normalize_part_name(_parse_root_rels(
        _parse_xml(rels_entry.data, "_rels/.rels")))
    if target not in entries:
        _fail("主文档关系目标不存在")

    main_parts = []
    for name in entries:
        if name.endswith("/"):
            continue
        content_type = _content_type_of(name, defaults, overrides)
        if content_type in _MAIN_CONTENT_TYPES:
            main_parts.append((name, _MAIN_CONTENT_TYPES[content_type]))
    if len(main_parts) != 1:
        _fail("包中必须恰好有一个标准主文档部件")
    main_name, doc_type = main_parts[0]
    if main_name != target:
        _fail("主文档部件与 officeDocument 关系目标不一致")

    root = _parse_xml(entries[main_name].data, "主文档")
    if root.tag != _MAIN_ROOTS[doc_type]:
        _fail("主文档根元素与声明类型不符")
    return doc_type
