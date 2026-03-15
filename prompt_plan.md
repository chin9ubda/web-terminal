# 스크롤 위치 초기화 버그 수정 계획

## 이전 계획

### SFTP 파일 전송 기능 (구현 중)
- SSH 세션에서 원격 파일 목록 조회/다운로드/업로드
- 로컬 터미널에서도 파일 관리

### SSH 호스트 접속 기능 (완료)
- 로컬/SSH 연결 선택, 호스트 프리셋, 비밀번호/키 인증

---

## 현재 계획: 스크롤이 맨 위로 올라가는 버그 수정

### 버그 현상
- 터미널에서 위로 스크롤하여 이전 출력을 보고 있는 중에 스크롤이 갑자기 맨 위로 점프

### 원인 분석

**핵심 원인: `fitAddon.fit()` 호출 시 스크롤 위치 미보존**

`handleResize()` → `fitAddon.fit()` 실행 경로:
1. `window resize` 이벤트 (브라우저 크기 변경)
2. `visualViewport resize` 이벤트 (모바일 키보드 열림/닫힘)
3. 툴바 토글 버튼 클릭

**문제 흐름:**
```
사용자가 위로 스크롤 → resize 이벤트 발생 →
container.style.height 변경 → fitAddon.fit() 호출 →
xterm.js가 rows 재계산 → 버퍼 reflow →
viewport scrollTop이 0으로 리셋 → 스크롤이 맨 위로 점프
```

**코드 위치:** `index.html:1447-1462`
```javascript
function handleResize() {
  if (resizeRaf) return;
  resizeRaf = requestAnimationFrame(() => {
    resizeRaf = null;
    if (!fitAddon) return;
    // ... container height 변경 ...
    fitAddon.fit();  // ← 여기서 스크롤 위치 손실
  });
}
```

### 수정 방안

#### 변경 파일: `public/index.html` (1곳)

**`handleResize()` 함수 수정** (라인 1447-1462):

`fitAddon.fit()` 호출 전후로 스크롤 위치를 저장/복원:

```javascript
function handleResize() {
  if (resizeRaf) return;
  resizeRaf = requestAnimationFrame(() => {
    resizeRaf = null;
    if (!fitAddon || !term) return;

    // 1. fit() 전: 현재 스크롤 위치 저장
    const savedViewportY = term.buffer.active.viewportY;
    const isAtBottom = savedViewportY >= term.buffer.active.baseY;

    const container = document.getElementById('terminal-container');
    if (window.visualViewport) {
      const statusBar = document.getElementById('status-bar');
      const toolbar = document.getElementById('key-toolbar');
      const textBar = document.getElementById('text-input-bar');
      const used = statusBar.offsetHeight + toolbar.offsetHeight + textBar.offsetHeight;
      container.style.height = (window.visualViewport.height - used) + 'px';
    }
    fitAddon.fit();

    // 2. fit() 후: 스크롤 위치 복원
    //    - 맨 아래에 있었으면 → 맨 아래 유지
    //    - 위로 스크롤 중이었으면 → 저장 위치로 복원
    if (isAtBottom) {
      term.scrollToBottom();
    } else {
      term.scrollToLine(savedViewportY);
    }
  });
}
```

**핵심 로직:**
- `viewportY`: 현재 뷰포트 최상단 라인 번호
- `baseY`: 스크롤백 버퍼에서 화면 시작점 (= 총 라인 - 화면 행 수)
- `viewportY >= baseY` → 사용자가 맨 아래에 있음 → 새 출력 따라가야 함
- `viewportY < baseY` → 사용자가 위로 스크롤한 상태 → 위치 보존

### 리스크
- **LOW**: `term.scrollToLine()`은 xterm.js 내부에서 범위 클램핑하므로 out-of-bounds 걱정 없음
- **LOW**: `isAtBottom` 판정으로 새 출력 도착 시 자동 스크롤도 정상 동작

### 영향 범위
- 변경 파일: 1개 (`public/index.html`)
- 변경 함수: 1개 (`handleResize`)
- 변경 라인: ~6줄 추가

### 검증 방법
1. 터미널에서 `seq 1 1000` 실행 → 위로 스크롤 → 브라우저 크기 변경 → 스크롤 위치 유지 확인
2. 모바일에서 위로 스크롤 → 텍스트 입력 터치(키보드 열림) → 스크롤 위치 유지 확인
3. 맨 아래 상태에서 새 출력 발생 → 자동 스크롤 정상 동작 확인
