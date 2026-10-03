"""准入库自动化测试。"""

import struct
import unittest
import zlib

from vault_admission import AdmissionDecision, check_admission
from vault_admission.ooxml import DocumentType

CT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
OFFICE_DOC_REL = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
)
DOCX_MAIN_CT = (
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
)
XLSX_MAIN_CT = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
)
DOCX_ROOT = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>'
XLSX_ROOT = '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"/>'


def _compress(data: bytes) -> bytes:
    obj = zlib.compressobj(9, zlib.DEFLATED, -15)
    return obj.compress(data) + obj.flush()


def build_zip(entries, comment: bytes = b"") -> bytes:
    """手工构造 ZIP。entries: (名称, 数据, 压缩方式, 是否用数据描述符, 描述符是否带签名)。"""
    out = bytearray()
    centrals = []
    for name, data, method, use_dd, dd_sig in entries:
        name_bytes = name.encode("utf-8")
        offset = len(out)
        compressed = _compress(data) if method == 8 else data
        crc = zlib.crc32(data)
        flags = 0x800 | (0x08 if use_dd else 0)
        if use_dd:
            out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method,
                               0, 0, 0, 0, 0, len(name_bytes), 0) + name_bytes
        else:
            out += struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, flags, method,
                               0, 0, crc, len(compressed), len(data),
                               len(name_bytes), 0) + name_bytes
        out += compressed
        if use_dd:
            if dd_sig:
                out += struct.pack("<I", 0x08074B50)
            out += struct.pack("<III", crc, len(compressed), len(data))
        centrals.append(struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, 0, 0,
            crc, len(compressed), len(data), len(name_bytes), 0, 0, 0, 0, 0,
            offset) + name_bytes)
    cd_offset = len(out)
    for central in centrals:
        out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(centrals),
                       len(centrals), len(out) - cd_offset, cd_offset,
                       len(comment)) + comment
    return bytes(out)


def content_types(overrides=(), defaults=(("rels",
                                           "application/vnd.openxmlformats-package.relationships+xml"),
                                          ("xml", "application/xml"))) -> str:
    parts = [f'<Types xmlns="{CT_NS}">']
    for ext, ct in defaults:
        parts.append(f'<Default Extension="{ext}" ContentType="{ct}"/>')
    for part, ct in overrides:
        parts.append(f'<Override PartName="{part}" ContentType="{ct}"/>')
    parts.append("</Types>")
    return "".join(parts)


def root_rels(target: str, target_mode: str = "") -> str:
    mode = f' TargetMode="{target_mode}"' if target_mode else ""
    return (f'<Relationships xmlns="{REL_NS}">'
            f'<Relationship Id="rId1" Type="{OFFICE_DOC_REL}" '
            f'Target="{target}"{mode}/></Relationships>')


def docx_package(main_path="odd/place/main.xml", use_dd=True, dd_sig=True,
                 comment=b"") -> bytes:
    return build_zip([
        ("[Content_Types].xml",
         content_types(overrides=[(f"/{main_path}", DOCX_MAIN_CT)]).encode(),
         8, use_dd, dd_sig),
        ("_rels/.rels", root_rels(main_path).encode(), 8, use_dd, dd_sig),
        (main_path, DOCX_ROOT.encode(), 8, use_dd, dd_sig),
    ], comment=comment)


class AdmissionTest(unittest.TestCase):
    def test_descriptor_unusual_path_and_whitelist(self) -> None:
        # 带数据描述符（有/无签名混合）、归档注释，主文档不在常用目录。
        blob = build_zip([
            ("[Content_Types].xml",
             content_types(overrides=[("/odd/place/main.xml", DOCX_MAIN_CT)]).encode(),
             8, True, True),
            ("_rels/.rels", root_rels("odd/place/main.xml").encode(), 0, True, False),
            ("odd/place/main.xml", DOCX_ROOT.encode(), 8, False, False),
        ], comment=b"vault note")
        result = check_admission(blob, frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.ACCEPTED)
        self.assertIs(result.document_type, DocumentType.DOCX)
        # 白名单按真实类型生效：仅放行 XLSX 时拒绝该 DOCX。
        result = check_admission(blob, frozenset({DocumentType.XLSX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)
        self.assertIs(result.document_type, DocumentType.DOCX)

    def test_type_not_derived_from_names(self) -> None:
        # 主文档路径看似 word 目录，内容类型与根元素才是判型依据。
        blob = build_zip([
            ("[Content_Types].xml",
             content_types(overrides=[("/word/document.xml", XLSX_MAIN_CT)]).encode(),
             8, False, False),
            ("_rels/.rels", root_rels("word/document.xml").encode(), 8, False, False),
            ("word/document.xml", XLSX_ROOT.encode(), 8, False, False),
        ])
        result = check_admission(blob, frozenset({DocumentType.XLSX}))
        self.assertIs(result.decision, AdmissionDecision.ACCEPTED)
        self.assertIs(result.document_type, DocumentType.XLSX)
        result = check_admission(blob, frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)

    def test_mixed_two_main_documents_rejected(self) -> None:
        blob = build_zip([
            ("[Content_Types].xml",
             content_types(overrides=[("/word/document.xml", DOCX_MAIN_CT),
                                      ("/xl/workbook.xml", XLSX_MAIN_CT)]).encode(),
             8, False, False),
            ("_rels/.rels", root_rels("word/document.xml").encode(), 8, False, False),
            ("word/document.xml", DOCX_ROOT.encode(), 8, False, False),
            ("xl/workbook.xml", XLSX_ROOT.encode(), 8, False, False),
        ])
        result = check_admission(
            blob, frozenset({DocumentType.DOCX, DocumentType.XLSX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)
        self.assertIsNone(result.document_type)

    def test_not_zip_rejected(self) -> None:
        result = check_admission(b"not a zip at all",
                                 frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)

    def test_encrypted_entry_rejected(self) -> None:
        blob = bytearray(docx_package(use_dd=False))
        # 将中央目录与本地头的标志位都置上加密位（位0）。
        blob[6] |= 0x01  # 本地头 flags 低字节（签名4 + 版本2 之后）
        cd_pos = blob.rfind(b"PK\x01\x02")
        blob[cd_pos + 6] |= 0x01
        result = check_admission(bytes(blob), frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)

    def test_dtd_rejected(self) -> None:
        evil = ('<?xml version="1.0"?><!DOCTYPE w:document [<!ENTITY x "y">]>'
                + DOCX_ROOT)
        blob = build_zip([
            ("[Content_Types].xml",
             content_types(overrides=[("/m.xml", DOCX_MAIN_CT)]).encode(),
             8, False, False),
            ("_rels/.rels", root_rels("m.xml").encode(), 8, False, False),
            ("m.xml", evil.encode(), 8, False, False),
        ])
        result = check_admission(blob, frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)

    def test_external_main_relationship_rejected(self) -> None:
        blob = build_zip([
            ("[Content_Types].xml",
             content_types(overrides=[("/m.xml", DOCX_MAIN_CT)]).encode(),
             8, False, False),
            ("_rels/.rels",
             root_rels("m.xml", target_mode="External").encode(), 8, False, False),
            ("m.xml", DOCX_ROOT.encode(), 8, False, False),
        ])
        result = check_admission(blob, frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)

    def test_trailing_bytes_rejected(self) -> None:
        blob = docx_package(use_dd=False) + b"\x00"
        result = check_admission(blob, frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)

    def test_backslash_name_rejected(self) -> None:
        blob = build_zip([
            ("[Content_Types].xml",
             content_types(overrides=[("/m.xml", DOCX_MAIN_CT)]).encode(),
             8, False, False),
            ("_rels/.rels", root_rels("m.xml").encode(), 8, False, False),
            ("m.xml", DOCX_ROOT.encode(), 8, False, False),
            ("evil\\..xml", b"x", 0, False, False),
        ])
        result = check_admission(blob, frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)

    def test_wrong_root_namespace_rejected(self) -> None:
        # 同名元素但命名空间不符，不算匹配。
        blob = build_zip([
            ("[Content_Types].xml",
             content_types(overrides=[("/m.xml", DOCX_MAIN_CT)]).encode(),
             8, False, False),
            ("_rels/.rels", root_rels("m.xml").encode(), 8, False, False),
            ("m.xml", b'<document xmlns="http://example.com/fake"/>', 8, False, False),
        ])
        result = check_admission(blob, frozenset({DocumentType.DOCX}))
        self.assertIs(result.decision, AdmissionDecision.REJECTED)


if __name__ == "__main__":
    unittest.main()
