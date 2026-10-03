"""保险库文档准入库：依据真实类型与调用方白名单决定是否准入。"""

from .admission import AdmissionDecision, AdmissionResult, check_admission

__all__ = ["AdmissionDecision", "AdmissionResult", "check_admission"]
