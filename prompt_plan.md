# SFTP 파일 전송 기능 구현 계획

## 이전 계획

### SSH 호스트 접속 기능 (완료)
- 로컬/SSH 연결 선택, 호스트 프리셋, 비밀번호/키 인증
- 상태: 구현 완료 (b92ee81)

---

## 현재 계획: SFTP 파일 전송

### 요구사항
- SSH 세션에서 원격 파일 목록 조회/다운로드/업로드
- 로컬 터미널에서도 파일 관리
- 디렉토리 생성/삭제, 파일 삭제/이름 변경
- 모바일 최적화

### 아키텍처
```
Browser ←HTTP REST API→ server.py ←asyncssh SFTP→ Remote Files
Browser ←HTTP REST API→ server.py ←os/pathlib→ Local Files
```

### 구현 단계

#### Phase 1a: file_manager.py (신규)
- FileManager 추상 클래스
- LocalFileManager (os/pathlib)
- SFTPFileManager (asyncssh)

#### Phase 1b: server.py SFTP API
- 세션 레지스트리 (session_id → FileManager)
- REST API: GET /api/files, GET /api/files/download, POST /api/files/upload
- REST API: DELETE /api/files, POST /api/files/mkdir, POST /api/files/rename

#### Phase 2: index.html 파일 브라우저 UI
- 상태바에 Files 버튼
- 파일 브라우저 오버레이 (디렉토리 탐색, 파일 액션)
- 업로드/다운로드 로직
- 모바일 최적화

#### Phase 3: 보안 강화
- 경로 순회 방어 (realpath 검증)
- 업로드 크기 제한 (100MB)
- SFTP 세션 수명 동기화

### 파일 변경 요약
| 파일 | 현재 | 예상 |
|------|------|------|
| server.py | 501줄 | ~700줄 |
| file_manager.py | 신규 | ~165줄 |
| index.html | 1337줄 | ~1850줄 |

### 상태: 구현 중
