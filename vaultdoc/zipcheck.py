"""严格的单卷 ZIP 结构校验与解包。

只接受普通单卷 ZIP：Stored/Deflate、可选数据描述符、可选归档注释。
拒绝加密、ZIP64 以及任何不符合"本地条目序列 + 中央目录 + 结束记录"结构的字节。
"""
from __future__ import annotations

import binascii
import struct
import zlib
from dataclasses import dataclass, field

from .errors import Rejected

_SIG_LOCAL = 0x04034B50
_SIG_CENTRAL = 0x02014B50
_SIG_EOCD = 0x06054B50
_SIG_DESCRIPTOR = 0x08074B50

_METHOD_STORED = 0
_METHOD_DEFLATE = 8

_FLAG_ENCRYPTED = 0x0001
_FLAG_DESCRIPTOR = 0x0008

_EXTRA_ZIP64 = 0x0001

_EOCD_MIN_LEN = 22
_MAX_COMMENT = 0xFFFF


@dataclass
class ZipEntry:
    """一个已校验的 ZIP 条目。"""

    name: str = ""
    is_dir: bool = False
    data: bytes = b""


@dataclass
class ZipPackage:
    """通过结构校验的 ZIP 包。"""

    entries: list[ZipEntry] = field(default_factory=list)

    def names(self) -> list[str]:
        return [e.name for e in self.entries]


@dataclass
class _CentralRecord:
    name_raw: bytes
    flags: int
    method: int
    crc: int
    comp_size: int
    uncomp_size: int
    local_offset: int


def _validate_name(name: str) -> bool:
    """校验 ZIP 条目名（大小写敏感）。"""
    if not name:
        return False
    if "\\" in name:
        return False
    if name.startswith("/"):
        return False
    segments = name.split("/")
    if name.endswith("/"):
        segments = segments[:-1]
        if not segments:
            return False
    for seg in segments:
        if seg in ("", ".", ".."):
            return False
    return True


def _check_extra(extra: bytes) -> None:
    """拒绝 ZIP64 扩展字段。"""
    pos = 0
    while pos + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, pos)
        if header_id == _EXTRA_ZIP64:
            raise Rejected("ZIP64 不被支持")
        pos += 4 + size
    if pos != len(extra):
        raise Rejected("扩展字段格式损坏")


def _find_eocd(raw: bytes) -> tuple[int, int, int, int]:
    """定位唯一的结束记录，返回 (cd_count, cd_size, cd_offset, eocd_offset)。"""
    if len(raw) < _EOCD_MIN_LEN:
        raise Rejected("数据过短，不是 ZIP")
    sig = struct.pack("<I", _SIG_EOCD)
    earliest = max(0, len(raw) - _EOCD_MIN_LEN - _MAX_COMMENT)
    candidates: list[int] = []
    pos = len(raw) - _EOCD_MIN_LEN
    while pos >= earliest:
        idx = raw.rfind(sig, earliest, pos + len(sig))
        if idx < 0:
            break
        if idx + _EOCD_MIN_LEN <= len(raw):
            fields = struct.unpack_from("<IHHHHIIH", raw, idx)
            comment_len = fields[7]
            if idx + _EOCD_MIN_LEN + comment_len == len(raw):
                candidates.append(idx)
        pos = idx - 1
    if not candidates:
        raise Rejected("找不到 ZIP 结束记录")
    if len(candidates) > 1:
        raise Rejected("结束记录位置存在歧义")
    eocd_offset = candidates[0]
    (
        _sig,
        disk_no,
        cd_disk,
        count_disk,
        count_total,
        cd_size,
        cd_offset,
        _comment_len,
    ) = struct.unpack_from("<IHHHHIIH", raw, eocd_offset)
    if disk_no != 0 or cd_disk != 0:
        raise Rejected("不支持多卷 ZIP")
    if count_disk != count_total:
        raise Rejected("中央目录计数不一致")
    if count_total == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
        raise Rejected("ZIP64 不被支持")
    if cd_offset + cd_size != eocd_offset:
        raise Rejected("中央目录与结束记录之间存在空隙或重叠")
    return count_total, cd_size, cd_offset, eocd_offset


def _parse_central(raw: bytes, count: int, cd_size: int, cd_offset: int) -> list[_CentralRecord]:
    records: list[_CentralRecord] = []
    pos = cd_offset
    end = cd_offset + cd_size
    for _ in range(count):
        if pos + 46 > end:
            raise Rejected("中央目录截断")
        fields = struct.unpack_from("<IHHHHHHIIIHHHHHII", raw, pos)
        if fields[0] != _SIG_CENTRAL:
            raise Rejected("中央目录签名错误")
        (
            _sig,
            _ver_made,
            _ver_need,
            flags,
            method,
            _mtime,
            _mdate,
            crc,
            comp_size,
            uncomp_size,
            name_len,
            extra_len,
            comment_len,
            disk_start,
            _int_attr,
            _ext_attr,
            local_offset,
        ) = fields
        if disk_start != 0:
            raise Rejected("不支持多卷 ZIP")
        if flags & _FLAG_ENCRYPTED:
            raise Rejected("加密条目不被支持")
        if method not in (_METHOD_STORED, _METHOD_DEFLATE):
            raise Rejected(f"不支持的压缩方式: {method}")
        if comp_size == 0xFFFFFFFF or uncomp_size == 0xFFFFFFFF or local_offset == 0xFFFFFFFF:
            raise Rejected("ZIP64 不被支持")
        rec_end = pos + 46 + name_len + extra_len + comment_len
        if rec_end > end:
            raise Rejected("中央目录记录越界")
        name_raw = raw[pos + 46 : pos + 46 + name_len]
        _check_extra(raw[pos + 46 + name_len : pos + 46 + name_len + extra_len])
        records.append(
            _CentralRecord(
                name_raw=name_raw,
                flags=flags,
                method=method,
                crc=crc,
                comp_size=comp_size,
                uncomp_size=uncomp_size,
                local_offset=local_offset,
            )
        )
        pos = rec_end
    if pos != end:
        raise Rejected("中央目录长度与声明不符")
    return records


def _parse_local(raw: bytes, rec: _CentralRecord) -> tuple[int, int]:
    """校验本地头与中央目录一致，返回 (数据起始, 数据结束)。"""
    off = rec.local_offset
    if off + 30 > len(raw):
        raise Rejected("本地头越界")
    fields = struct.unpack_from("<IHHHHHIIIHH", raw, off)
    if fields[0] != _SIG_LOCAL:
        raise Rejected("本地头签名错误")
    (
        _sig,
        _ver_need,
        flags,
        method,
        _mtime,
        _mdate,
        crc,
        comp_size,
        uncomp_size,
        name_len,
        extra_len,
    ) = fields
    if flags != rec.flags:
        raise Rejected("本地头与中央目录标志不一致")
    if method != rec.method:
        raise Rejected("本地头与中央目录压缩方式不一致")
    data_start = off + 30 + name_len + extra_len
    if data_start > len(raw):
        raise Rejected("本地头越界")
    name_raw = raw[off + 30 : off + 30 + name_len]
    if name_raw != rec.name_raw:
        raise Rejected("本地头与中央目录名称不一致")
    _check_extra(raw[off + 30 + name_len : data_start])
    if flags & _FLAG_DESCRIPTOR:
        # 带数据描述符时本地头长度/CRC 通常为零；非零则必须与目录一致
        if crc not in (0, rec.crc) or comp_size not in (0, rec.comp_size) or uncomp_size not in (0, rec.uncomp_size):
            raise Rejected("本地头与中央目录长度或 CRC 不一致")
    else:
        if crc != rec.crc or comp_size != rec.comp_size or uncomp_size != rec.uncomp_size:
            raise Rejected("本地头与中央目录长度或 CRC 不一致")
    data_end = data_start + rec.comp_size
    if data_end > len(raw):
        raise Rejected("条目数据越界")
    return data_start, data_end


def _descriptor_size(raw: bytes, pos: int, rec: _CentralRecord) -> int:
    """确定数据描述符长度（12 或 16 字节），并校验其内容与目录一致。"""
    tail = raw[pos : pos + 16]
    if len(tail) >= 16 and struct.unpack_from("<I", tail, 0)[0] == _SIG_DESCRIPTOR:
        crc, comp, uncomp = struct.unpack_from("<III", tail, 4)
        if (crc, comp, uncomp) == (rec.crc, rec.comp_size, rec.uncomp_size):
            return 16
    if len(tail) >= 12:
        crc, comp, uncomp = struct.unpack_from("<III", tail, 0)
        if (crc, comp, uncomp) == (rec.crc, rec.comp_size, rec.uncomp_size):
            return 12
    raise Rejected("数据描述符与中央目录不一致")


def _decompress(method: int, comp: bytes, rec: _CentralRecord) -> bytes:
    if method == _METHOD_STORED:
        data = comp
    else:
        obj = zlib.decompressobj(-15)
        try:
            data = obj.decompress(comp, rec.uncomp_size + 1)
        except zlib.error as exc:
            raise Rejected(f"Deflate 解压失败: {exc}") from exc
        if not obj.eof:
            raise Rejected("压缩流未正常结束")
        if obj.unused_data:
            raise Rejected("压缩流结束后存在附加数据")
    if len(data) != rec.uncomp_size:
        raise Rejected("展开长度与声明不符")
    if binascii.crc32(data) & 0xFFFFFFFF != rec.crc:
        raise Rejected("CRC 校验失败")
    return data


def parse_zip(raw: bytes) -> ZipPackage:
    """解析并严格校验 ZIP 包，返回条目集合。"""
    count, cd_size, cd_offset, _eocd = _find_eocd(raw)
    records = _parse_central(raw, count, cd_size, cd_offset)

    # 名称规则与重复检测（大小写敏感）
    seen: set[str] = set()
    names: list[str] = []
    for rec in records:
        try:
            name = rec.name_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Rejected("条目名不是合法 UTF-8") from exc
        if not _validate_name(name):
            raise Rejected(f"非法条目名: {name!r}")
        if name in seen:
            raise Rejected(f"重复条目名: {name!r}")
        seen.add(name)
        names.append(name)

    # 本地条目必须连续、不重叠、恰好被目录引用一次
    spans: list[tuple[int, int, int]] = []  # (local_offset, entry_end, index)
    for idx, rec in enumerate(records):
        data_start, data_end = _parse_local(raw, rec)
        entry_end = data_end
        if rec.flags & _FLAG_DESCRIPTOR:
            entry_end += _descriptor_size(raw, data_end, rec)
        spans.append((rec.local_offset, entry_end, idx))
    spans.sort()
    expected = 0
    for local_offset, entry_end, _idx in spans:
        if local_offset != expected:
            raise Rejected("本地条目区域存在空隙或重叠")
        expected = entry_end
    if expected != cd_offset:
        raise Rejected("本地条目与中央目录之间存在多余字节")

    entries: list[ZipEntry] = []
    for rec, name in zip(records, names):
        name_len, extra_len = struct.unpack_from("<HH", raw, rec.local_offset + 26)
        data_start = rec.local_offset + 30 + name_len + extra_len
        comp = raw[data_start : data_start + rec.comp_size]
        is_dir = name.endswith("/")
        if is_dir and (rec.comp_size != 0 or rec.uncomp_size != 0):
            raise Rejected("目录条目不允许携带数据")
        data = _decompress(rec.method, comp, rec)
        entries.append(ZipEntry(name=name, is_dir=is_dir, data=data))
    return ZipPackage(entries=entries)
