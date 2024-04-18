package org.zerock.api01.security.exception;


import com.google.gson.Gson;
import org.springframework.http.MediaType;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Map;

public class AccessTokenException extends RuntimeException {
    // 토큰 예외 처리용
    // 1. AT 가 없는 경우 - 토큰이 없다는 메시지 전달
    // 2. AT 가 잘못된 경우 (서명변조, 기타 에러) - 잘못된 토큰이라는 메시지 전달
    // 3. AT 가 오래된(expired) 된 경우 - 갱신하라는 메시지 전달

    // 일반적으로 Access Token 의 값은 HTTP Header 중에 Authorization 을 이용함
    // Authorization 헤더는 type + 인증값으로 작성 됨 값들은 Basic, Bearer, Digest, HOBA, Mutual 등 이 있다.
    // JWT는 이중에 Bearer라는 타입을 이용함.
    TOKEN_ERROR token_error;

    public enum TOKEN_ERROR {  // enum으로 구성 나중에 에러 메시지 전송할 수 있는 구조로 작성
        UNACCEPT(401,"Token is null or too short"),
        BADTYPE(401, "Token type Bearer"),
        MALFORM(403, "Malformed Token"),
        BADSIGN(403, "BadSignatured Token"),
        EXPIRED(403, "Expired Token");

        private int status;
        private String msg;

        TOKEN_ERROR(int status, String msg){
            this.status = status;
            this.msg = msg;
        }

        public int getStatus() {
            return this.status;
        }

        public String getMsg() {
            return this.msg;
        }
    }

    public AccessTokenException(TOKEN_ERROR error){
        super(error.name());
        this.token_error = error;
    }

    public void sendResponseError(HttpServletResponse response){

        response.setStatus(token_error.getStatus());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();

        String responseStr = gson.toJson(Map.of("msg", token_error.getMsg(), "time", new Date()));

        try {
            response.getWriter().println(responseStr);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
