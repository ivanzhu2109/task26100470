"""准入库自动化测试。"""
from __future__ import annotations

import binascii
import struct
import zlib

import pytest

from vaultdoc import DocType, Rejected, admit

NS_CT = "http://schemas.openxmlformats.org/package/2006/content-types"
NS_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
NS_WORD = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS_SHEET = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL_OFFICE = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)
CT_DOCX = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
)
CT_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"

DOCX_XML = f'<w:document xmlns:w="{NS_WORD}"><w:body/></w:document>'.encode()
XLSX_XML = f'<workbook xmlns="{NS_SHEET}"><sheets/></workbook>'.encode()


def _deflate(data: bytes) -> bytes:
    obj = zlib.compressobj(9, zlib.DEFLATED, -15)
    return obj.compress(data) + obj.flush()


def build_zip(entries: list[dict], comment: bytes = b"") -> bytes:
    """手工构造 ZIP，支持数据描述符、注释及多种畸形选项。"""
    out = bytearray()
    central = bytearray()
    count = 0
    for e in entries:
        name = e["name"].encode("utf-8") if isinstance(e["name"], str) else e["name"]
        data = e.get("data", b"")
        method = e.get("method", 8)
        descriptor = e.get("descriptor", False)
        comp = data if method == 0 else _deflate(data)
        comp += e.get("comp_suffix", b"")
        crc = binascii.crc32(data) & 0xFFFFFFFF
        if e.get("corrupt_crc"):
            crc ^= 0xFF
        flags = 0x08 if descriptor else 0
        flags |= e.get("flag_extra", 0)
        out += e.get("gap_before", b"")
        local_offset = len(out)
        if descriptor:
            lh_crc, lh_comp, lh_uncomp = 0, 0, 0
        else:
            lh_crc, lh_comp, lh_uncomp = crc, len(comp), len(data)
        out += struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, flags, method, 0, 0,
            lh_crc, lh_comp, lh_uncomp, len(name), 0,
        )
        out += name
        out += comp
        if descriptor:
            if e.get("descriptor_sig", True):
                out += struct.pack("<I", 0x08074B50)
            out += struct.pack("<III", crc, len(comp), len(data))
        cd_crc = crc
        cd_comp = len(comp)
        cd_uncomp = len(data)
        if e.get("zip64_sizes"):
            cd_comp = cd_uncomp = 0xFFFFFFFF
        central += struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, 0, 0,
            cd_crc, cd_comp, cd_uncomp, len(name), 0, 0, 0, 0, 0, local_offset,
        )
        central += name
        count += 1
    cd_offset = len(out)
    out += central
    out += struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, count, count, len(central), cd_offset, len(comment)
    )
    out += comment
    return bytes(out)


def ct_xml(defaults=(), overrides=()) -> bytes:
    parts = [f'<Types xmlns="{NS_CT}">']
    for ext, ct in defaults:
        parts.append(f'<Default Extension="{ext}" ContentType="{ct}"/>')
    for part, ct in overrides:
        parts.append(f'<Override PartName="{part}" ContentType="{ct}"/>')
    parts.append("</Types>")
    return "".join(parts).encode()


def rels_xml(rels: list[tuple[str, str | None]]) -> bytes:
    parts = [f'<Relationships xmlns="{NS_REL}">']
    for i, (target, mode) in enumerate(rels):
        mode_attr = f' TargetMode="{mode}"' if mode else ""
        parts.append(
            f'<Relationship Id="rId{i + 1}" Type="{REL_OFFICE}" Target="{target}"{mode_attr}/>'
        )
    parts.append("</Relationships>")
    return "".join(parts).encode()


def make_pkg(main_path: str, main_ct: str, main_xml: bytes, **zip_opts) -> bytes:
    entries = [
        {"name": "[Content_Types].xml", "data": ct_xml(overrides=[(main_path, main_ct)])},
        {"name": "_rels/.rels", "data": rels_xml([(main_path, None)])},
        {"name": main_path, "data": main_xml},
    ]
    for e in entries:
        e.update(zip_opts)
    return build_zip(entries)


def make_docx(**kw) -> bytes:
    return make_pkg("word/document.xml", CT_DOCX, DOCX_XML, **kw)


def make_xlsx(**kw) -> bytes:
    return make_pkg("xl/workbook.xml", CT_XLSX, XLSX_XML, **kw)


# ---------- 必需场景 ----------

def test_docx_descriptor_unusual_path_and_whitelist():
    """带数据描述符、主文档不在常用目录：判型不依赖文件名，白名单按真实类型生效。"""
    entries = [
        {
            "name": "[Content_Types].xml",
            "data": ct_xml(overrides=[("/odd/place/core.bin", CT_DOCX)]),
            "method": 0,
        },
        {"name": "_rels/", "data": b"", "method": 0},
        {"name": "_rels/.rels", "data": rels_xml([("odd/place/%63ore.bin", None)])},
        {"name": "odd/place/core.bin", "data": DOCX_XML, "descriptor": True,
         "descriptor_sig": False},
    ]
    raw = build_zip(entries, comment=b"vault archive comment")
    assert admit(raw, [DocType.DOCX]) is DocType.DOCX
    assert admit(raw, ["docx", "xlsx"]) is DocType.DOCX
    with pytest.raises(Rejected):
        admit(raw, [DocType.XLSX])
    with pytest.raises(Rejected):
        admit(raw, [])


def test_dual_main_document_rejected():
    """双主文档混合包不得准入。"""
    entries = [
        {
            "name": "[Content_Types].xml",
            "data": ct_xml(overrides=[("word/document.xml", CT_DOCX), ("xl/workbook.xml", CT_XLSX)]),
        },
        {"name": "_rels/.rels", "data": rels_xml([("word/document.xml", None)])},
        {"name": "word/document.xml", "data": DOCX_XML},
        {"name": "xl/workbook.xml", "data": XLSX_XML},
    ]
    raw = build_zip(entries)
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX, DocType.XLSX])


# ---------- 正常类型识别 ----------

def test_xlsx_signed_descriptor():
    raw = make_xlsx(descriptor=True, descriptor_sig=True)
    assert admit(raw, [DocType.XLSX]) is DocType.XLSX
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])


def test_docx_plain():
    assert admit(make_docx(), [DocType.DOCX]) is DocType.DOCX


def test_directory_names_do_not_drive_detection():
    """主文档在 word/ 目录但内容类型与根元素都是 XLSX 时，应判为 XLSX。"""
    raw = make_pkg("word/document.xml", CT_XLSX, XLSX_XML)
    assert admit(raw, [DocType.XLSX]) is DocType.XLSX


# ---------- ZIP 结构 ----------

def test_trailing_junk_rejected():
    with pytest.raises(Rejected):
        admit(make_docx() + b"junk", [DocType.DOCX])


def test_prepended_junk_rejected():
    with pytest.raises(Rejected):
        admit(b"PK" + make_docx(), [DocType.DOCX])


def test_gap_between_entries_rejected():
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("word/document.xml", CT_DOCX)])},
        {"name": "_rels/.rels", "data": rels_xml([("word/document.xml", None)]),
         "gap_before": b"X"},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_encrypted_rejected():
    raw = make_docx(flag_extra=0x01)
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])


def test_zip64_rejected():
    raw = make_docx(zip64_sizes=True)
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])


def test_crc_mismatch_rejected():
    raw = make_docx(corrupt_crc=True)
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])


def test_deflate_trailing_data_rejected():
    raw = make_docx(comp_suffix=b"XX")
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])


def test_non_zip_rejected():
    with pytest.raises(Rejected):
        admit(b"not a zip at all", [DocType.DOCX])


@pytest.mark.parametrize("bad", ["a\\b", "/abs", "a//b", "a/./b", "a/../b", "a/b/.."])
def test_bad_entry_names_rejected(bad):
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("word/document.xml", CT_DOCX)])},
        {"name": "_rels/.rels", "data": rels_xml([("word/document.xml", None)])},
        {"name": "word/document.xml", "data": DOCX_XML},
        {"name": bad, "data": b"x"},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_duplicate_entry_name_rejected():
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("word/document.xml", CT_DOCX)])},
        {"name": "_rels/.rels", "data": rels_xml([("word/document.xml", None)])},
        {"name": "word/document.xml", "data": DOCX_XML},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


# ---------- OPC 规则 ----------

def test_missing_content_types_rejected():
    entries = [
        {"name": "_rels/.rels", "data": rels_xml([("word/document.xml", None)])},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_missing_root_rels_rejected():
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("word/document.xml", CT_DOCX)])},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_external_relationship_rejected():
    raw = make_pkg("word/document.xml", CT_DOCX, DOCX_XML)
    # 替换 rels 为外部关系
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("word/document.xml", CT_DOCX)])},
        {"name": "_rels/.rels",
         "data": rels_xml([("word/document.xml", "External")])},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])
    assert admit(raw, [DocType.DOCX]) is DocType.DOCX


def test_two_office_document_rels_rejected():
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("word/document.xml", CT_DOCX)])},
        {"name": "_rels/.rels",
         "data": rels_xml([("word/document.xml", None), ("word/document.xml", None)])},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_target_missing_rejected():
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("word/document.xml", CT_DOCX)])},
        {"name": "_rels/.rels", "data": rels_xml([("word/other.xml", None)])},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_dtd_rejected():
    xml = b'<!DOCTYPE w:document [<!ENTITY x "y">]>' + DOCX_XML
    raw = make_pkg("word/document.xml", CT_DOCX, xml)
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])


def test_entity_decl_in_content_types_rejected():
    ct = (b'<!DOCTYPE Types [<!ENTITY e "v">]>'
          + ct_xml(overrides=[("word/document.xml", CT_DOCX)]))
    entries = [
        {"name": "[Content_Types].xml", "data": ct},
        {"name": "_rels/.rels", "data": rels_xml([("word/document.xml", None)])},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_wrong_root_namespace_rejected():
    xml = b'<document xmlns="http://example.com/fake"/>'
    raw = make_pkg("word/document.xml", CT_DOCX, xml)
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])


def test_truncated_main_document_rejected():
    raw = make_pkg("word/document.xml", CT_DOCX, DOCX_XML[:20])
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])


def test_duplicate_override_after_normalization_rejected():
    ct = ct_xml(overrides=[("/a/b.xml", CT_DOCX), ("a/b.xml", CT_DOCX)])
    entries = [
        {"name": "[Content_Types].xml", "data": ct},
        {"name": "_rels/.rels", "data": rels_xml([("a/b.xml", None)])},
        {"name": "a/b.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_query_string_in_target_rejected():
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("word/document.xml", CT_DOCX)])},
        {"name": "_rels/.rels", "data": rels_xml([("word/document.xml?x=1", None)])},
        {"name": "word/document.xml", "data": DOCX_XML},
    ]
    with pytest.raises(Rejected):
        admit(build_zip(entries), [DocType.DOCX])


def test_default_extension_case_insensitive():
    """未命中 Override 时由 Default 按扩展名匹配，扩展名不区分 ASCII 大小写。"""
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(defaults=[("BiN", CT_DOCX)])},
        {"name": "_rels/.rels", "data": rels_xml([("odd/CORE.bin", None)])},
        {"name": "odd/CORE.bin", "data": DOCX_XML},
    ]
    assert admit(build_zip(entries), [DocType.DOCX]) is DocType.DOCX


def test_override_percent_decoding():
    """Override 与关系目标按 UTF-8 百分号解码一次并允许一个开头斜杠。"""
    entries = [
        {"name": "[Content_Types].xml",
         "data": ct_xml(overrides=[("/odd/%70lace/core.bin", CT_DOCX)])},
        {"name": "_rels/.rels", "data": rels_xml([("/odd/place/core.bin", None)])},
        {"name": "odd/place/core.bin", "data": DOCX_XML},
    ]
    assert admit(build_zip(entries), [DocType.DOCX]) is DocType.DOCX


def test_whitelist_unknown_value_rejected():
    with pytest.raises(Rejected):
        admit(make_docx(), ["pptx"])


def test_real_type_must_hit_whitelist():
    """识别成功但未命中白名单时不得准入。"""
    raw = make_xlsx()
    with pytest.raises(Rejected):
        admit(raw, [DocType.DOCX])
