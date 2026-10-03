"""错误类型定义。"""


class Rejected(Exception):
    """文件不符合准入条件时抛出。"""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason
