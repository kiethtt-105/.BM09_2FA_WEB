# BÁO CÁO LỖI — HUIT 2FA System
> Phạm vi: `setup_2fa`, `verify_2fa`, `utils.py`, `models.py`, `views.py`  
> Phân loại: Logic Bug · HTML/Backend Mismatch · Security Issue

---

## NHÓM 1 — HTML ↔ BACKEND MISMATCH (gây lỗi chức năng)

### BUG-1 · `setup_2fa.html` — `user.email` không tồn tại trong context
**Mức độ:** 🔴 Critical (TemplateError — trang bị crash)

**Vị trí:** `setup_2fa.html` dòng 343, 358
```html
Gửi mã OTP đến <strong>{{ user.email }}</strong>
Mã đã gửi · kiểm tra hộp thư {{ user.email }}
```

**Nguyên nhân:** View truyền `user_email` vào context, **không phải** `user`:
```python
# views.py dòng 687
context = {
    'user_email': request.user.email or 'Chưa có email',
    ...
}
```

Template dùng `{{ user.email }}` — Django sẽ resolve `user` từ `RequestContext` (có `request.user`), nên không crash ngay, **nhưng** nếu context processor `django.contrib.auth.context_processors.auth` bị thiếu thì `user` sẽ là `AnonymousUser` → `user.email` trả về `''` thay vì email thật.

**Sửa:** Dùng nhất quán `{{ user_email }}` trong template:
```html
Gửi mã OTP đến <strong>{{ user_email }}</strong>
Mã đã gửi · kiểm tra hộp thư {{ user_email }}
```

---

### BUG-2 · `setup_2fa.html` — TOTP form POST thiếu `?method=` trong action
**Mức độ:** 🔴 Critical (TOTP verify bị route sai method)

**Vị trí:** `setup_2fa.html` — form TOTP (khoảng dòng 296)
```html
<form method="POST" id="totp-form">
  {% csrf_token %}
  <input type="hidden" name="method" value="app">
  ...
  <button name="verify_app_otp" ...>
```

**Nguyên nhân:** Form POST không có `action="?method=app"`. View đọc `method` từ **GET**:
```python
method = request.GET.get('method', 'app')
```

Khi POST, `request.GET.get('method')` = `None` → fallback `'app'` ✓ — **may mắn hoạt động** nhưng lệ thuộc vào fallback. Nếu user đang ở `?method=totp`, POST sẽ cần URL giữ `?method=totp`.  

Tuy nhiên `name="method"` trong `<input hidden>` là **POST body**, không phải GET param — view không đọc nó:
```python
method = request.GET.get('method', 'app')  # Chỉ đọc GET
```

**Sửa:** Thêm `action="?method=app"` vào form và **xóa** `<input type="hidden" name="method">` thừa:
```html
<form method="POST" action="?method=app" id="totp-form">
  {% csrf_token %}
  <!-- bỏ input hidden method -->
```

Tương tự, form HOTP:
```html
<form method="POST" action="?method=hotp">
```

---

### BUG-3 · `setup_2fa.html` — Nút "Tắt TOTP" không yêu cầu nhập OTP xác nhận
**Mức độ:** 🟠 High (UX/Security — tắt 2FA không cần xác thực)

**Vị trí:** `setup_2fa.html` dòng 315
```html
<form method="POST">
  <input type="hidden" name="action" value="disable_app">
  <button class="btn btn-danger">Tắt TOTP</button>
</form>
```

**Nguyên nhân:** View `setup_2fa` xử lý `disable_app` bằng cách kiểm tra TOTP code:
```python
elif request.POST.get('action') == 'disable_app':
    raw_secret = profile.decrypt_secret()
    if raw_secret and verify_totp(raw_secret, request.POST.get('otp_code', '').strip()):
```

Nhưng HTML **không có field nhập `otp_code`** — `otp_code` sẽ là chuỗi rỗng → `verify_totp` trả `False` → **không bao giờ tắt được** TOTP từ trang này. Người dùng bấm nút, không có gì xảy ra, không có thông báo lỗi rõ ràng.

**Sửa:** Thêm input OTP vào form tắt TOTP (giống pattern ở dashboard), hoặc đổi `disable_app` ở setup page → redirect về dashboard với `action=disable_app`.

---

### BUG-4 · `verify_2fa.html` — Tab method bị hardcode `?method=totp` thay vì `m.key`
**Mức độ:** 🟠 High (tab TOTP luôn link tới `?method=totp`, không theo `m.key`)

**Vị trí:** `verify_2fa.html` dòng 132
```html
{% for m in methods %}
  {% if m.key == 'totp' or m.key == 'app' %}
    <a href="?method=totp" class="method {% if method == 'totp' %}active{% endif %}">
```

**Nguyên nhân:** View truyền `methods` dưới dạng list of dicts với `key` là `'totp'`. Link đúng, nhưng active check là `method == 'totp'` — trong khi view redirect ban đầu về `enabled_keys[0]`, nếu user có HOTP trước TOTP thì first key là `hotp`, redirect về `?method=hotp` đúng, nhưng tab TOTP vẫn link đúng `?method=totp`. Điều này thực ra hoạt động nhưng:

**Lỗi thực sự:** Nếu `m.key == 'app'` (không xảy ra vì view dùng `'totp'`), href sẽ sai. View `verify_2fa` xây `methods` với `key='totp'`, còn `setup_2fa` context hay `login_view` message dùng `'Authenticator'`. Không có nhất quán.

---

### BUG-5 · `setup_2fa.html` — CSS/Style bị duplicate (có 2 `<style>` block, 2 `<body>`)
**Mức độ:** 🟡 Medium (render bị lỗi trên một số browser)

**Nguyên nhân:** File `setup_2fa.html` được nối từ 2 bản — khi xem full file thấy CSS classes như `.otp-row`, `.otp-box`, `.btn`, `.alert` được định nghĩa **hai lần**, và có 2 thẻ `</style></head><body>` liền nhau. Phần từ `/* OTP inputs */` trở đi là duplicate nguyên xi của phần CSS đầu.

**Hậu quả:** HTML không hợp lệ — trình duyệt render "best effort" nhưng nội dung từ block `<style>` thứ 2 nằm trong `<body>` thành text node → hiện ra chữ CSS trên màn hình.

**Sửa:** Xóa toàn bộ phần từ dòng `/* OTP inputs */` đến `</head><body>` thứ hai.

---

## NHÓM 2 — LOGIC BUG (backend)

### BUG-6 · `verify_register_otp` — Dùng cả `PendingRegistration` VÀ `EmailOTP` song song nhưng không nhất quán
**Mức độ:** 🔴 Critical (có thể xác thực với OTP sai)

**Nguyên nhân:** `register()` view tạo đồng thời:
1. `PendingRegistration` (lưu hash OTP)
2. `EmailOTP` (qua `generate_and_send_email_otp`, action=`'register'`, `user=None`)

`verify_register_otp()` chỉ verify qua `PendingRegistration.verify()` — **đúng**. Nhưng sau verify thành công có cleanup `EmailOTP`:
```python
EmailOTP.objects.filter(email_sent=email, action='register', user__isnull=True, is_active=True).update(is_active=False)
```

**Vấn đề:** `EmailOTP.verify_otp_pending()` (classmethod trong models) cũng có thể được gọi từ nơi khác với cùng email → có thể verify song song qua 2 path khác nhau. Thiết kế 2 model cho cùng 1 mục đích = dư thừa và nguy cơ race condition.

---

### BUG-7 · `setup_2fa` view — `verify_app_otp` không check `method` GET param khi POST
**Mức độ:** 🟠 High

```python
elif method in ('app', 'totp'):
    if 'verify_app_otp' in request.POST:
```

Nếu user ở `?method=email` nhưng submit form có `name="verify_app_otp"` (bị tamper), view sẽ vào nhánh email vì `method='email'` → không xử lý `verify_app_otp`. OK trong trường hợp này. Nhưng ngược lại nếu `method='app'` và POST có `verify_email_otp` → bị bỏ qua. Không có fallback thông báo lỗi.

---

### BUG-8 · `utils.py` — `generate_and_send_email_otp` invalidate OTP cũ chỉ khi `user is not None`
**Mức độ:** 🟠 High (OTP đăng ký `user=None` không bị invalidate khi resend)

```python
if user is not None:
    EmailOTP.objects.filter(user=user, action=action, is_used=False, is_active=True).update(is_active=False)
```

Khi `action='register'`, `user=None` → **điều kiện `if user is not None` = False** → các OTP cũ `user=None` không bị invalidate. Nếu user bấm "Gửi lại OTP" nhiều lần → nhiều `EmailOTP` active song song với `user=None, email_sent=<same_email>`.

`PendingRegistration` được xóa và tạo lại đúng trong resend flow, nên verify chính vẫn an toàn. Nhưng `EmailOTP` bị rác trong DB.

**Sửa:** Thêm nhánh invalidate theo `email_sent`:
```python
if user is not None:
    EmailOTP.objects.filter(user=user, action=action, is_used=False, is_active=True).update(is_active=False)
else:
    # register flow: user=None, phân biệt qua email_sent
    if 'email' in locals() or email:
        EmailOTP.objects.filter(user__isnull=True, email_sent=email, action=action, is_used=False, is_active=True).update(is_active=False)
```
(Hoặc truyền `email` vào hàm và xử lý trong utils)

---

### BUG-9 · `verify_2fa` — HOTP counter tăng trước khi `login()` thành công
**Mức độ:** 🟠 High (counter lệch nếu login sau HOTP thất bại vì lý do khác)

```python
elif method == 'hotp' and profile.has_hotp:
    raw_secret = profile.decrypt_hotp_secret()
    if raw_secret:
        ok, new_counter = verify_hotp(raw_secret, profile.hotp_counter, code)
        if ok:
            profile.hotp_counter = new_counter
            profile.save(update_fields=['hotp_counter'])  # ← counter tăng ngay
            valid = True
```

Counter tăng trước khi `login()` — nếu sau đó có exception (hiếm nhưng có thể), user bị desync counter mà chưa được login.

**Sửa:** Defer `save()` counter sau `login()`, hoặc dùng `select_for_update()` + transaction.

---

### BUG-10 · `verify_2fa` — `send_email_code` không check rate limit trước khi gửi
**Mức độ:** 🟡 Medium (có thể spam email OTP)

```python
if action == 'send_email_code' and profile.has_email_otp:
    generate_and_send_email_otp(...)
    return redirect(...)
```

Không check `OTPAttempt.is_blocked()` trước khi gửi — attacker có thể spam POST `action=send_email_code` để trigger liên tục email gửi đến nạn nhân.

**Sửa:** Dùng `cache.get`/`cache.set` với key `email_otp_cooldown:{user.id}` (30 giây cooldown) hoặc check `OTPAttempt`.

---

## NHÓM 3 — FIDO2 ISSUES

### BUG-11 · `fido2_auth_begin` — `credentials=[]` bỏ qua credential hints
**Mức độ:** 🟠 High (FIDO2 roaming key có thể không hiện đúng)

```python
auth_data, state = server_local.authenticate_begin(
    credentials=[],   # ← empty
    ...
)
```

Truyền `credentials=[]` → browser không nhận `allowCredentials` hint từ server side. View tự build `allowCredentials` thủ công trong JSON response — **nhưng** đây là thông tin "hints" phía client, không được verify server-side. Server vẫn chấp nhận bất kỳ credential nào vì `credentials=[]` trong `authenticate_begin`.

**Sửa:** Truyền danh sách credentials thực:
```python
from fido2.webauthn import PublicKeyCredentialDescriptor
cred_list = [
    PublicKeyCredentialDescriptor(type='public-key', id=websafe_decode(pk.credential_id))
    for pk in passkeys
]
auth_data, state = server_local.authenticate_begin(credentials=cred_list, ...)
```

---

### BUG-12 · `fido2_auth_complete` — không tăng `sign_count` an toàn (clone detection thiếu)
**Mức độ:** 🟠 High

```python
passkey.sign_count = auth_data_obj.counter
passkey.save()
```

Không kiểm tra `auth_data_obj.counter > passkey.sign_count` (counter phải tăng dần — nếu không là dấu hiệu authenticator bị clone). FIDO2 spec yêu cầu từ chối khi `new_counter <= stored_counter` (trừ khi cả hai = 0).

**Sửa:**
```python
if auth_data_obj.counter > 0 and auth_data_obj.counter <= passkey.sign_count:
    return JsonResponse({'status': 'error', 'message': 'Phát hiện authenticator có thể bị sao chép'}, status=400)
passkey.sign_count = auth_data_obj.counter
passkey.save()
```

---

## NHÓM 4 — MINOR / UX

### BUG-13 · `verify_register_otp.html` — Countdown timer sai (600s thay vì 300s hiển thị)
**Vị trí:** `verify_register_otp.html`
```javascript
let t = 600;
const timerEl = document.getElementById('timer');
// timerEl ban đầu hiển thị "300"
```

`timerEl` khởi tạo text `300` trong HTML nhưng JS countdown từ `t=600`. Không nhất quán.

**Sửa:** Đổi `let t = 300` (email OTP đăng ký hiệu lực 10 phút = 600s, nhưng resend cooldown là 5 phút = 300s — cần quyết định timer này đếm cái gì).

---

### BUG-14 · `setup_2fa` — `setup_token` có thể là `''` khi HOTP session còn
**Vị trí:** `views.py` dòng 840
```python
else:
    setup_token = request.session.get('temp_hotp_token', '')
```

Nếu `temp_hotp_token` không còn trong session (bị expire hoặc server restart) → `setup_token = ''` → template render `<input value="">` → POST sẽ bị từ chối bởi `hmac.compare_digest('', session_token)` → user bị loop không ra.

**Sửa:** Nếu `temp_hotp_token` không có, tạo mới luôn thay vì trả `''`.

---

## TÓM TẮT ƯU TIÊN

| #   | Bug                                          | Mức    | Ảnh hưởng              |
|-----|----------------------------------------------|--------|------------------------|
| 5   | CSS duplicate / double `<body>` trong HTML   | 🟡     | Render vỡ              |
| 1   | `user.email` vs `user_email` trong context   | 🔴     | Email không hiện đúng  |
| 2   | TOTP form thiếu `action="?method=app"`       | 🔴     | Route sai method       |
| 3   | Nút tắt TOTP không có OTP input             | 🟠     | Tắt TOTP không được    |
| 8   | OTP `user=None` không bị invalidate khi resend | 🟠  | Rác DB + logic sai     |
| 10  | `send_email_code` không rate limit           | 🟡     | Email spam             |
| 11  | FIDO2 `credentials=[]` trong auth_begin      | 🟠     | Security bypass risk   |
| 12  | FIDO2 không check clone detection            | 🟠     | FIDO2 spec violation   |
| 9   | HOTP counter tăng trước `login()`            | 🟠     | Counter desync         |
