from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.utils import websafe_encode
import json

# 1. Cấu hình định danh (RP - Relying Party)
# LƯU Ý: Khi chạy thật trên ngrok, ID này phải là domain ngrok của bạn
RP_ID = "localhost" 
RP_NAME = "Dự án MFA của Kiệt"
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)

def simulate_registration_begin():
    # Giả lập User
    user = {"id": b"user_id_001", "name": "kiet07", "displayName": "Tuấn Kiệt"}

    # Tạo dữ liệu đăng ký
    registration_data, state = server.register_begin(user)

    # In ra dữ liệu mà Backend sẽ gửi cho Browser
    print("--- DỮ LIỆU GỬI XUỐNG FRONTEND ---")
    print(json.dumps(dict(registration_data), indent=4, default=websafe_encode))
    
    return state

if __name__ == "__main__":
    simulate_registration_begin()
    print("\n[OK] Backend đã tạo Challenge thành công!")