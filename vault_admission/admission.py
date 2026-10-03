"""准入决策：真实类型识别 + 调用方白名单。"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Optional

from .ooxml import DocumentType, PackageError, detect_document_type
from .zip_reader import ZipFormatError, read_zip_entries


class AdmissionDecision(Enum):
    """准入结论。"""

    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class AdmissionResult:
    """准入检查结果。"""

    decision: AdmissionDecision
    document_type: Optional[DocumentType]
    reason: str


def check_admission(
    blob: bytes,
    allowed_types: FrozenSet[DocumentType],
) -> AdmissionResult:
    """依据真实类型与调用方白名单决定是否准入。

    文件名与调用方声称的类型不参与判定；识别成功也必须命中白名单。
    """
    try:
        entries = read_zip_entries(blob)
        document_type = detect_document_type(entries)
    except (ZipFormatError, PackageError) as exc:
        return AdmissionResult(AdmissionDecision.REJECTED, None, str(exc))
    if document_type not in allowed_types:
        return AdmissionResult(
            AdmissionDecision.REJECTED,
            document_type,
            f"真实类型 {document_type.value} 不在调用方白名单中",
        )
    return AdmissionResult(AdmissionDecision.ACCEPTED, document_type, "准入")
