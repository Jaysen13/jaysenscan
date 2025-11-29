from dataclasses import dataclass, asdict
from typing import Dict, Optional

# 定义请求数据类型
@dataclass
class JaysenReqData:
    # 请求方法（GET/POST等）
    method: str
    # 完整请求参数和值
    paramters: Dict[str,str]
    # 请求头（字典格式，key为头名称，value为头值）
    headers: Dict[str, str]
    # 请求体（GET请求为空字符串，POST/PUT可能有内容）
    body: str

# 定义响应数据类型
@dataclass
class JaysenRespData:
    # 响应头（字典格式，key为头名称，value为头值）
    headers: Dict[str, str]
    # 响应体
    body: str