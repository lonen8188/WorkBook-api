package org.zerock.api01.security.exception;


import com.google.gson.Gson;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Map;

public class RefreshTokenException extends RuntimeException {
    // 토큰 재발생용 코드
    // 전송된 json 데이터에서 at와 rt를 추출
    // at를 검사해서 토큰이 없거나 잘못된 토큰인경우 에러메시지 전송
    // rt를 검사해서 토큰이 없거나 잘못, 만료된 토큰인 경우 에러메시지 전송
    // 새로운 at 생성
    // 만료기한이 얼마남지 않은 경우 새로운 rt 생성
    // at, rt 전송

    private ErrorCase errorCase;

    public enum ErrorCase {
        NO_ACCESS, NO_REFRESH, OLD_REFRESH
    }

    public RefreshTokenException(ErrorCase errorCase) {
        super(errorCase.name());
        this.errorCase = errorCase;
    }

    public void sendResponseError(HttpServletResponse response) {

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();

        String responseStr = gson.toJson(Map.of("msg", errorCase.name(), "time", new Date()));

        try {
            response.getWriter().println(responseStr);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
