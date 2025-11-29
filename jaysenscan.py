from flask import Flask, request, jsonify
from __jaysendata import JaysenReqData,JaysenRespData
app = Flask(__name__)

# 对请求数据包进行解密操作
@app.route('/RequestReceived', methods=['POST'])
def request_received():
    request_json = request.get_json()
    # 初始化原始数据
    jaysendata = JaysenReqData(
        method=request_json.get("method", ""),
        paramters=request_json.get("paramters", {}),
        headers=request_json.get("headers", {}),
        body=request_json.get("body", ""),
    )
# ===============================在此区域对请求数据包进行加密========================================


#==============================================================================================
    # 返回修改后的数据包
    return jsonify(jaysendata)

# 对解密后的请求进行加密操作
@app.route('/RequestToBeSent', methods=['POST'])
def handle_request():
    request_json = request.get_json()
    # 初始化原始数据
    jaysendata = JaysenReqData(
        method=request_json.get("method", ""),
        paramters=request_json.get("paramters", {}),
        headers=request_json.get("headers", {}),
        body=request_json.get("body", ""),
    )
# ===============================在此区域对请求数据包进行解密还原========================================

# ==============================================================================================
    # 返回修改后的数据包
    return jsonify(jaysendata)

# 解密响应数据包
@app.route('/ResponseReceived', methods=['POST'])
def ResponseReceived():
    resp_json = request.get_json()
    jaysendata = JaysenRespData(
        headers=resp_json.get("headers"),
        body=resp_json.get("body")
    )
# ===============================在此区域对响应数据包进行解密========================================

# ==============================================================================================
    # 返回修改后的数据包
    return jsonify(jaysendata)

#加密响应数据包
@app.route('/ResponseToBeSent', methods=['POST'])
def ResponseToBeSent():
    resp_json = request.get_json()
    jaysendata = JaysenRespData(
        headers=resp_json.get("headers"),
        body=resp_json.get("body")
    )
# ===============================在此区域对响应数据包进行加密还原========================================

# ==============================================================================================
    # 不修改响应包
    return jsonify(jaysendata)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)