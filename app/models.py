"""Pydantic 数据模型"""

from pydantic import BaseModel
from typing import Optional, List, Union, Any


class Message(BaseModel):
    role: str
    content: Union[str, List[Any]]


class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[Message]
    stream: Optional[bool] = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None


class SafeResponse(BaseModel):
    blocked: bool
    threat_type: Optional[str]
    reason: Optional[str]
    source: str
    score: float
