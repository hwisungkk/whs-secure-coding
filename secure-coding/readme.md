# 🛡️ Secure Coding 기반 중고거래 플랫폼

Flask 기반 웹 플랫폼으로, 회원가입, 상품 등록, 1:1 채팅, 신고, 송금 기능을 갖춘 보안 중심의 중고거래 시스템입니다.

---

## 🔐 개발 중 발견된 보안 약점 및 적용한 보완 조치

1. **비밀번호 평문 저장**
   - 🔥 문제: 초기에는 사용자 비밀번호가 평문으로 DB에 저장됨
   - ✅ 조치: `werkzeug.security`의 `generate_password_hash`, `check_password_hash`로 안전한 해시 처리 적용

2. **입력값 검증 미흡**
   - 🔥 문제: 상품 등록, 채팅, 송금 등에서 사용자 입력값에 대한 길이 및 형식 검증이 누락됨
   - ✅ 조치: `WTForms`의 `validators`를 통해 필수 입력, 길이, 숫자 범위, 정규식 패턴 등 적용

3. **XSS(Cross-Site Scripting) 가능성**
   - 🔥 문제: 사용자 입력이 필터 없이 출력되어 XSS 가능
   - ✅ 조치: Jinja2의 `{{ 변수|e }}` escape 적용 + 클라이언트 측 `escapeHtml()` 함수 추가

4. **SQL Injection 가능성**
   - 🔥 문제: 사용자 입력이 SQL 쿼리에 직접 삽입되며 공격 가능
   - ✅ 조치: 모든 DB 쿼리에 파라미터 바인딩 (`?`) 방식 적용

5. **CSRF 보호 미적용**
   - 🔥 문제: POST 요청에 CSRF 방어 로직이 없음
   - ✅ 조치: `Flask-WTF` 기반 `FlaskForm`으로 CSRF 토큰 적용

6. **권한 검증 누락**
   - 🔥 문제: 상품 수정/삭제, 신고, 송금 등에서 접근 제어 미비
   - ✅ 조치: `session['user_id']` 기반 인증 로직 추가 및 관리자 기능은 `@admin_required` 데코레이터로 보호

7. **중복 신고 허용**
   - 🔥 문제: 하나의 사용자가 같은 대상에게 여러 번 신고 가능
   - ✅ 조치: 동일 사용자가 동일 대상에게 신고한 횟수를 확인하고, 3회 이상은 차단 처리

8. **송금 시 자기 자신에게 송금 가능**
   - 🔥 문제: 로그인한 사용자가 본인 계정으로 송금할 수 있었음
   - ✅ 조치: `if sender_id == recipient_id:` 조건 추가로 자기 자신 송금 차단

9. **송금/충전 금액 비정상 입력**
   - 🔥 문제: 음수, 0원, 텍스트 등 잘못된 금액이 입력되어도 처리 가능
   - ✅ 조치: `WTForms`의 `NumberRange(min=1)` 및 `IntegerField`를 통해 서버 측 검증

10. **계좌번호 형식 무검증**
   - 🔥 문제: 충전 시 계좌번호 입력값에 대한 형식 검증이 없어 이상 값 허용
   - ✅ 조치: 정규표현식 기반 `Regexp(r'^\d{3}-\d{2}-\d{5}$')` 검증 적용

11. **비밀번호 보안 강도 미검증**
   - 🔥 문제: 비밀번호가 너무 단순해도 등록 가능
   - ✅ 조치: 최소 8자, 숫자/대소문자/특수문자 포함 정규표현식 기반 강도 검증

12. **상품 수정/삭제 시 권한 미검증**
   - 🔥 문제: 로그인만 하면 모든 상품에 접근 가능
   - ✅ 조치: 상품 소유자와 현재 세션 사용자 ID가 일치하는지 확인

---

## ⚙️ 환경 설정 및 실행 방법

### ✅ 요구사항

- Python 3.9+
- Flask
- Flask-WTF
- Flask-SocketIO
- WTForms
- (권장) Conda 가상환경 사용

### ✅ 설치 방법

```bash
# 프로젝트 클론
git clone https://github.com/hwisungkk/whs-secure-coding.git
cd whs-secure-coding

# Conda 환경 설정
conda env create -f environment.yaml
conda activate secure-coding
```

### ✅ 실행

```bash
python app.py
```

브라우저에서 http://localhost:5000 접속  
최초 실행 시 DB가 자동 초기화됨
