"""OPC（Open Packaging Conventions）层面的类型判定。

依据 [Content_Types].xml 与 _rels/.rels 判定真实主文档类型，
不依赖文件名、扩展名或调用方声称的类型。
"""
from __future__ import annotations

import urllib.parse
import xml.parsers.expat
from dataclasses import dataclass, field
from enum import Enum

from .errors import Rejected
from .zipcheck import ZipPackage

_NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
_NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_NS_WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_NS_SHEET = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

_REL_OFFICE_DOCUMENT = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)

_CT_DOCX_MAIN = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
)
_CT_XLSX_MAIN = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
_MAIN_CTS = (_CT_DOCX_MAIN, _CT_XLSX_MAIN)


class DocType(Enum):
    DOCX = "docx"
    XLSX = "xlsx"


@dataclass
class _Node:
    tag: str
    attrib: dict[str, str] = field(default_factory=dict)
    children: list["_Node"] = field(default_factory=list)


def _parse_xml(data: bytes, what: str) -> _Node:
    """解析 XML，要求完整、良构，拒绝 DTD 与实体声明。"""
    stack: list[_Node] = []
    root: list[_Node] = []

    def _q(name: str) -> str:
        if "}" in name:
            uri, local = name.split("}", 1)
            return "{" + uri + "}" + local
        return name

    def start(tag: str, attrib: dict[str, str]) -> None:
        node = _Node(tag=_q(tag), attrib={_q(k): v for k, v in attrib.items()})
        if stack:
            stack[-1].children.append(node)
        else:
            root.append(node)
        stack.append(node)

    def end(_tag: str) -> None:
        stack.pop()

    def forbidden(*_args: object) -> None:
        raise Rejected(f"{what}: 不允许 DTD 或实体声明")

    parser = xml.parsers.expat.ParserCreate(namespace_separator="}")
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    try:
        parser.Parse(data, True)
    except Rejected:
        raise
    except xml.parsers.expat.ExpatError as exc:
        raise Rejected(f"{what}: XML 不良构或不完整: {exc}") from exc
    if len(root) != 1:
        raise Rejected(f"{what}: 缺少唯一的根元素")
    return root[0]


def _ascii_lower(text: str) -> str:
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in text)


def _normalize_part_name(raw_target: str, what: str) -> str:
    """百分号解码一次（UTF-8），允许去掉一个开头斜杠，套用 ZIP 名称规则。"""
    if "?" in raw_target or "#" in raw_target:
        raise Rejected(f"{what}: 不允许查询串或片段")
    try:
        decoded = urllib.parse.unquote(raw_target, encoding="utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise Rejected(f"{what}: 百分号编码不是合法 UTF-8") from exc
    if "?" in decoded or "#" in decoded:
        raise Rejected(f"{what}: 不允许查询串或片段")
    if decoded.startswith("/"):
        decoded = decoded[1:]
    if not decoded or decoded.startswith("/"):
        raise Rejected(f"{what}: 非法的部件路径")
    if "\\" in decoded:
        raise Rejected(f"{what}: 不允许反斜杠")
    segments = decoded.split("/")
    if decoded.endswith("/"):
        raise Rejected(f"{what}: 部件路径不能是目录")
    for seg in segments:
        if seg in ("", ".", ".."):
            raise Rejected(f"{what}: 非法的路径段")
    return decoded


def _parse_content_types(data: bytes) -> tuple[dict[str, str], dict[str, str]]:
    """返回 (Default 表: 小写扩展名 -> CT, Override 表: 规范化部件名 -> CT)。"""
    root = _parse_xml(data, "[Content_Types].xml")
    if root.tag != f"{{{_NS_CT}}}Types":
        raise Rejected("[Content_Types].xml: 根元素必须是 Types")
    defaults: dict[str, str] = {}
    overrides: dict[str, str] = {}
    for child in root.children:
        if child.tag == f"{{{_NS_CT}}}Default":
            ext = child.attrib.get("Extension")
            ct = child.attrib.get("ContentType")
            if not ext or not ct:
                raise Rejected("[Content_Types].xml: Default 缺少属性")
            key = _ascii_lower(ext)
            if key in defaults:
                raise Rejected(f"[Content_Types].xml: 重复的 Default 扩展名 {key!r}")
            defaults[key] = ct
        elif child.tag == f"{{{_NS_CT}}}Override":
            part = child.attrib.get("PartName")
            ct = child.attrib.get("ContentType")
            if not part or not ct:
                raise Rejected("[Content_Types].xml: Override 缺少属性")
            key = _normalize_part_name(part, "[Content_Types].xml Override")
            if key in overrides:
                raise Rejected(f"[Content_Types].xml: 重复的 Override 部件 {key!r}")
            overrides[key] = ct
    return defaults, overrides


def _parse_root_rels(data: bytes) -> str:
    """解析 _rels/.rels，返回唯一 officeDocument 关系的规范化目标部件名。"""
    root = _parse_xml(data, "_rels/.rels")
    if root.tag != f"{{{_NS_REL}}}Relationships":
        raise Rejected("_rels/.rels: 根元素必须是 Relationships")
    targets: list[str] = []
    for child in root.children:
        if child.tag != f"{{{_NS_REL}}}Relationship":
            continue
        if child.attrib.get("Type") != _REL_OFFICE_DOCUMENT:
            continue
        mode = child.attrib.get("TargetMode", "Internal")
        if mode != "Internal":
            raise Rejected("_rels/.rels: officeDocument 必须是内部关系")
        target = child.attrib.get("Target")
        if not target:
            raise Rejected("_rels/.rels: officeDocument 缺少 Target")
        targets.append(_normalize_part_name(target, "_rels/.rels Target"))
    if len(targets) != 1:
        raise Rejected("_rels/.rels: 必须恰好有一个 officeDocument 关系")
    return targets[0]


def _extension_of(part_name: str) -> str | None:
    last = part_name.rsplit("/", 1)[-1]
    if "." in last and not last.endswith("."):
        return _ascii_lower(last.rsplit(".", 1)[-1])
    return None


def detect_type(pkg: ZipPackage) -> DocType:
    """依据包结构与内容判定真实文档类型。"""
    files = {e.name: e.data for e in pkg.entries if not e.is_dir}
    ct_data = files.get("[Content_Types].xml")
    if ct_data is None:
        raise Rejected("缺少 [Content_Types].xml")
    rels_data = files.get("_rels/.rels")
    if rels_data is None:
        raise Rejected("缺少 _rels/.rels")

    defaults, overrides = _parse_content_types(ct_data)
    target = _parse_root_rels(rels_data)
    if target not in files:
        raise Rejected("officeDocument 目标部件不存在")

    def content_type_of(part_name: str) -> str | None:
        if part_name in overrides:
            return overrides[part_name]
        ext = _extension_of(part_name)
        return defaults.get(ext) if ext is not None else None

    main_parts = [name for name in files if content_type_of(name) in _MAIN_CTS]
    if len(main_parts) != 1:
        raise Rejected("主文档类型部件必须恰好有一个")
    if main_parts[0] != target:
        raise Rejected("主文档部件与 officeDocument 关系目标不一致")

    main_ct = content_type_of(target)
    if main_ct == _CT_DOCX_MAIN:
        expected = (DocType.DOCX, _NS_WORD, "document")
    elif main_ct == _CT_XLSX_MAIN:
        expected = (DocType.XLSX, _NS_SHEET, "workbook")
    else:
        raise Rejected("主文档部件内容类型不是标准 DOCX/XLSX")

    doc_type, ns, local = expected
    root = _parse_xml(files[target], "主文档")
    if root.tag != f"{{{ns}}}{local}":
        raise Rejected(f"主文档根元素必须是 {ns} 命名空间下的 {local}")
    return doc_type
