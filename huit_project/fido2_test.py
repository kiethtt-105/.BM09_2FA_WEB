from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.utils import websafe_decode, websafe_encode
import json

# 1. Cấu hình ban đầu (Relying Party)
rp = PublicKeyCredentialRpEntity(id="localhost", name="Django FIDO2 Test")
server = Fido2Server(rp)

# Giả lập database tạm thời
user_db = {
    "id": b"user_id_123",
    "name": "duy@example.com",
    "display_name": "Duy User"
}
credentials = [] # Lưu các credential sau khi đăng ký thành công

def step_1_registration_begin():
    """Tạo dữ liệu để gửi cho Client đăng ký (Hiện mã QR chứa thông tin này)"""
    registration_data, state = server.register_begin(
        user=user_db,
        user_verification="discouraged" # Hoặc "required" nếu muốn dùng PIN/Vân tay
    )
    # 'state' phải được lưu vào session ở phía Django
    return registration_data, state

def step_2_registration_complete(state, client_data, attestation_object):
    """Xác thực phản hồi từ Client và lưu credential"""
    auth_data = server.register_complete(state, client_data, attestation_object)
    credentials.append(auth_data.credential_data)
    print("✅ Đăng ký thành công!")
    return auth_data.credential_data

def step_3_authentication_begin():
    """Tạo thử thách để Login"""
    if not credentials:
        return "Chưa có thiết bị nào được đăng ký!"
    
    auth_data, state = server.authenticate_begin(credentials)
    return auth_data, state

def step_4_authentication_complete(state, credential_id, client_data, auth_data, signature):
    """Kiểm tra chữ ký khi Login"""
    server.authenticate_complete(
        state,
        credentials,
        credential_id,
        client_data,
        auth_data,
        signature
    )
    print("✅ Đăng nhập thành công bằng FIDO2!")

# --- CHẠY THỬ LOGIC ---
print("--- TEST ĐĂNG KÝ ---")
reg_data, reg_state = step_1_registration_begin()
# Ở bước này, reg_data sẽ được encode thành JSON gửi cho trình duyệt/app quét.
print(f"Challenge tạo ra: {websafe_encode(reg_state['challenge'])}")

