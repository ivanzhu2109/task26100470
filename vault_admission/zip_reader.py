"""严格 ZIP 解析：仅接受普通单卷 ZIP 的 Stored/Deflate 条目。"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass
from typing import Dict, List


class ZipFormatError(ValueError):
    """ZIP 结构不符合准入要求。"""


@dataclass(frozen=True)
class ZipEntry:
    """单个 ZIP 条目的已验证信息。"""

    name: str
    data: bytes


_LFH_SIG = 0x04034B50
_DD_SIG = 0x08074B50
_CDH_SIG = 0x02014B50
_EOCD_SIG = 0x06054B50

_METHOD_STORED = 0
_METHOD_DEFLATE = 8

_FLAG_DATA_DESCRIPTOR = 1 << 3
# 仅允许：位1/2（Deflate 级别提示）、位3（数据描述符）、位11（UTF-8 名称）。
# 位0（加密）、位5（补丁）、位6（强加密）、位13（中央目录加密）等一律拒绝。
_ALLOWED_FLAGS = (1 << 1) | (1 << 2) | _FLAG_DATA_DESCRIPTOR | (1 << 11)

_EXTRA_ZIP64 = 0x0001

_U16_MAX = 0xFFFF
_U32_MAX = 0xFFFFFFFF

_ABS_DRIVE_RE = re.compile(r"^[A-Za-z]:")


@dataclass(frozen=True)
class _CentralEntry:
    name_bytes: bytes
    flags: int
    method: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    local_offset: int


def _fail(message: str) -> None:
    raise ZipFormatError(message)


def _find_eocd(blob: bytes) -> tuple:
    """定位结束记录，要求其注释恰好延伸到文件末尾。"""
    if len(blob) < 22:
        _fail("文件过短，缺少结束记录")
    sig = struct.pack("<I", _EOCD_SIG)
    pos = len(blob) - 22
    start = max(0, pos - _U16_MAX)
    while pos >= start:
        if blob[pos:pos + 4] == sig:
            fields = struct.unpack_from("<HHHHIIH", blob, pos + 4)
            if pos + 22 + fields[6] == len(blob):
                return (pos,) + fields
        pos -= 1
    _fail("未找到有效的结束记录")


def _check_extra(extra: bytes) -> None:
    pos = 0
    while pos + 4 <= len(extra):
        tag, size = struct.unpack_from("<HH", extra, pos)
        if tag == _EXTRA_ZIP64:
            _fail("拒绝 ZIP64 扩展字段")
        pos += 4 + size
    if pos != len(extra):
        _fail("扩展字段长度损坏")


def validate_entry_name(name: str) -> None:
    if not name:
        _fail("空条目名")
    if name.startswith("/") or _ABS_DRIVE_RE.match(name):
        _fail("条目名为绝对路径")
    if "\\" in name:
        _fail("条目名含反斜杠")
    segments = name.split("/")
    if segments[-1] == "":
        segments.pop()  # 目录项末尾斜杠
    for segment in segments:
        if segment == "":
            _fail("条目名含空路径段")
        if segment in (".", ".."):
            _fail("条目名含单点或双点路径段")


def _parse_central_directory(blob: bytes, offset: int, size: int) -> List[_CentralEntry]:
    entries: List[_CentralEntry] = []
    pos = offset
    end = offset + size
    while pos < end:
        if pos + 46 > end or struct.unpack_from("<I", blob, pos)[0] != _CDH_SIG:
            _fail("中央目录损坏")
        (flags, method, crc, comp, uncomp,
         name_len, extra_len, comment_len,
         disk_start, local_offset) = struct.unpack_from("<xxxxHHxxxxIIIHHHHxxxxxxI", blob, pos + 4)
        name_end = pos + 46 + name_len
        extra_end = name_end + extra_len
        next_pos = extra_end + comment_len
        if next_pos > end:
            _fail("中央目录条目越界")
        name_bytes = blob[pos + 46:name_end]
        extra = blob[name_end:extra_end]
        if disk_start != 0:
            _fail("拒绝多卷归档")
        if flags & ~_ALLOWED_FLAGS:
            _fail("条目使用了不允许的标志位（如加密）")
        if method not in (_METHOD_STORED, _METHOD_DEFLATE):
            _fail("不支持的压缩方式")
        if _U32_MAX in (crc, comp, uncomp) or local_offset == _U32_MAX:
            _fail("拒绝 ZIP64 占位值")
        _check_extra(extra)
        entries.append(_CentralEntry(name_bytes, flags, method, crc, comp, uncomp, local_offset))
        pos = next_pos
    return entries


def _inflate(method: int, compressed: bytes, expected_size: int) -> bytes:
    if method == _METHOD_STORED:
        if len(compressed) != expected_size:
            _fail("Stored 条目长度与声明不一致")
        return compressed
    decomp = zlib.decompressobj(-15)
    out = decomp.decompress(compressed, expected_size + 1)
    if len(out) != expected_size:
        _fail("展开长度与声明不一致")
    if not decomp.eof:
        _fail("压缩流未正常结束")
    if decomp.unused_data or decomp.unconsumed_tail:
        _fail("压缩流结束后存在附加数据")
    return bytes(out)


def read_zip_entries(blob: bytes) -> Dict[str, ZipEntry]:
    """解析并校验 ZIP，返回名称到条目的映射。"""
    (eocd_pos, disk, cd_disk, disk_entries, total,
     cd_size, cd_offset, _comment_len) = _find_eocd(blob)
    if disk != 0 or cd_disk != 0:
        _fail("拒绝多卷归档")
    if disk_entries != total:
        _fail("结束记录中的条目计数不一致")
    if total == _U16_MAX or cd_size == _U32_MAX or cd_offset == _U32_MAX:
        _fail("拒绝 ZIP64 占位值")
    if cd_offset + cd_size != eocd_pos:
        _fail("中央目录与结束记录之间存在额外字节")

    centrals = _parse_central_directory(blob, cd_offset, cd_size)
    if len(centrals) != total:
        _fail("中央目录条目数与结束记录不一致")
    by_offset: Dict[int, _CentralEntry] = {}
    for central in centrals:
        if central.local_offset in by_offset:
            _fail("多个目录条目引用同一本地条目")
        by_offset[central.local_offset] = central

    result: Dict[str, ZipEntry] = {}
    pos = 0
    matched = 0
    while pos < cd_offset:
        if pos + 30 > cd_offset or struct.unpack_from("<I", blob, pos)[0] != _LFH_SIG:
            _fail("本地条目区存在非条目字节")
        (flags, method, crc, comp, uncomp,
         name_len, extra_len) = struct.unpack_from("<xxHHxxxxIIIHH", blob, pos + 4)
        name_end = pos + 30 + name_len
        extra_end = name_end + extra_len
        if extra_end > cd_offset:
            _fail("本地条目头越界")
        name_bytes = blob[pos + 30:name_end]
        _check_extra(blob[name_end:extra_end])

        central = by_offset.get(pos)
        if central is None:
            _fail("本地条目未被中央目录引用")
        matched += 1
        if central.name_bytes != name_bytes:
            _fail("本地条目与目录的名称不一致")
        if central.flags != flags:
            _fail("本地条目与目录的标志不一致")
        if central.method != method:
            _fail("本地条目与目录的压缩方式不一致")
        if flags & _FLAG_DATA_DESCRIPTOR:
            if crc != 0 or comp != 0 or uncomp != 0:
                _fail("使用数据描述符时本地头的长度与CRC必须为零")
        elif (crc, comp, uncomp) != (central.crc, central.compressed_size,
                                     central.uncompressed_size):
            _fail("本地条目与目录的长度或CRC不一致")

        data_start = extra_end
        data_end = data_start + central.compressed_size
        if data_end > cd_offset:
            _fail("条目数据越界")
        cursor = data_end
        if flags & _FLAG_DATA_DESCRIPTOR:
            if cursor + 4 <= len(blob) and \
                    struct.unpack_from("<I", blob, cursor)[0] == _DD_SIG:
                cursor += 4
            if cursor + 12 > len(blob):
                _fail("数据描述符越界")
            dd_crc, dd_comp, dd_uncomp = struct.unpack_from("<III", blob, cursor)
            cursor += 12
            if (dd_crc, dd_comp, dd_uncomp) != (central.crc, central.compressed_size,
                                                central.uncompressed_size):
                _fail("数据描述符与目录不一致")

        data = _inflate(method, blob[data_start:data_end], central.uncompressed_size)
        if zlib.crc32(data) != central.crc:
            _fail("条目 CRC 校验失败")
        try:
            name = name_bytes.decode("utf-8")
        except UnicodeDecodeError:
            _fail("条目名不是有效 UTF-8")
        validate_entry_name(name)
        if name in result:
            _fail("重复的条目名")
        result[name] = ZipEntry(name, data)
        pos = cursor

    if pos != cd_offset:
        _fail("本地条目区与中央目录之间存在额外字节")
    if matched != len(centrals):
        _fail("存在未被本地条目匹配的目录条目")
    return result
