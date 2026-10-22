# [한글 기능 설명]
# 기능: LocalCode Review MCP 서버의 실행 진입점.
# 시작점/입력: Python 실행과 고정할 예제/JDK 경로 인자.
# 이어지는 기능: server.main → 공식 SDK의 STDIO 핸드셰이크 → 등록한 도구 호출.
# 주의: 표준 출력은 MCP 메시지 전용이며 일반 로그는 stderr로만 보낸다.
from localcode_review_mcp.server import main


if __name__ == "__main__":
    main()
