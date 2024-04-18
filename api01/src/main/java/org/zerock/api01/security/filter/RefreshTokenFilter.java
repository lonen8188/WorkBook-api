package org.zerock.api01.security.filter;


import com.google.gson.Gson;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.MediaType;
import org.springframework.web.filter.OncePerRequestFilter;
//import org.zerock.api01.security.exception.RefreshTokenException;
import org.zerock.api01.security.exception.RefreshTokenException;
import org.zerock.api01.util.JWTUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class RefreshTokenFilter  extends OncePerRequestFilter {

    private final String refreshPath;

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        if (!path.equals(refreshPath)) {
            log.info("skip refresh token filter.....");
            filterChain.doFilter(request, response);
            return;
        }

        log.info("Refresh Token Filter...run..............1");

        //전송된 JSON에서 accessToken과 refreshToken을 얻어온다. 828 추가
        Map<String, String> tokens = parseRequestJSON(request);  // 하단에 parseRequestJSON메서드 필수

        String accessToken = tokens.get("accessToken");
        String refreshToken = tokens.get("refreshToken");

        log.info("accessToken: " + accessToken);
        log.info("refreshToken: " + refreshToken);

        //Secured GET /files/refreshTest.html
        //2024-04-17T15:22:15.896+09:00 DEBUG 8656 --- [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Securing POST /refreshToken
        //2024-04-17T15:22:15.897+09:00  INFO 8656 --- [nio-8080-exec-2] o.z.a.s.filter.RefreshTokenFilter        : Refresh Token Filter...run..............1
        //2024-04-17T15:22:15.910+09:00  INFO 8656 --- [nio-8080-exec-2] o.z.a.s.filter.RefreshTokenFilter        : accessToken: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJhcGl1c2VyMTAiLCJpYXQiOjE3MTMzMzQzNDAsImV4cCI6MTcxMzQyMDc0MH0.DhBUm7_D-IYSZNJh2IenklKzFkQd3G_7nv8wT2HeW28
        //2024-04-17T15:22:15.910+09:00  INFO 8656 --- [nio-8080-exec-2] o.z.a.s.filter.RefreshTokenFilter        : refreshToken: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJhcGl1c2VyMTAiLCJpYXQiOjE3MTMzMzQzNDAsImV4cCI6MTcxNTkyNjM0MH0.sC4SyNz4x6P_PiLI8HadEMGrc6WUuPHnBCqGekmtLWE

        try{  // 829 추가 하단에 예외처리 활용
            checkAccessToken(accessToken);
        }catch(RefreshTokenException refreshTokenException){
            refreshTokenException.sendResponseError(response);
            return; // 더이상 실행할 필요 없음.
        }

        // 830 추가 rt 예외 처리용 하단 메서드 활용
        Map<String, Object> refreshClaims = null;

        try {

            refreshClaims = checkRefreshToken(refreshToken);
            log.info(refreshClaims);

        }catch(RefreshTokenException refreshTokenException){
            refreshTokenException.sendResponseError(response);
            return;
        }

        // 831 추가 Refresh Token의 유효시간이 얼마 남지 않은 경우
        Integer exp = (Integer)refreshClaims.get("exp");

        Date expTime = new Date(Instant.ofEpochMilli(exp).toEpochMilli() * 1000);

        Date current = new Date(System.currentTimeMillis());

        //만료 시간과 현재 시간의 간격 계산
        //만일 3일 미만인 경우에는 Refresh Token도 다시 생성
        long gapTime = (expTime.getTime() - current.getTime());

        log.info("-----------------------------------------");
        log.info("current: " + current);
        log.info("expTime: " + expTime);
        log.info("gap: " + gapTime );

        String mid = (String)refreshClaims.get("mid");

        //이상태까지 오면 무조건 AccessToken은 새로 생성
        String accessTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 1);

        String refreshTokenValue = tokens.get("refreshToken");

        //RefrshToken이 3일도 안남았다면..
        if(gapTime < (1000 * 60  * 60  ) ){
            //if(gapTime < (1000 * 60 * 60 * 24 * 3  ) ){
            log.info("new Refresh Token required...  ");
            refreshTokenValue = jwtUtil.generateToken(Map.of("mid", mid), 30);
        }

        log.info("Refresh Token result...................."); // 832 추가
        log.info("accessToken: " + accessTokenValue);
        log.info("refreshToken: " + refreshTokenValue);

        sendTokens(accessTokenValue, refreshTokenValue, response); // 하단에 메서드 추가 필수


    }

    private Map<String,String> parseRequestJSON(HttpServletRequest request) {  // 828 추가

        //JSON 데이터를 분석해서 mid, mpw 전달 값을 Map으로 처리
        try(Reader reader = new InputStreamReader(request.getInputStream())){

            Gson gson = new Gson();

            return gson.fromJson(reader, Map.class);

        }catch(Exception e){
            log.error(e.getMessage());
        }
        return null;
    }

    private void checkAccessToken(String accessToken)throws RefreshTokenException { // 829 추가
        //  문제가 생기면 RefreshTokenException을 전달 하여 처리함.
        try{
            jwtUtil.validateToken(accessToken);
        }catch (ExpiredJwtException expiredJwtException){
            log.info("Access Token has expired"); // 로그만 출력 함.
        }catch(Exception exception){
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.NO_ACCESS);
        }
    }

    // 829 추가 : rt 검사용 , 존재와 만료일이 지났는지 확인, 새로운 토큰 생성을 위해서 mid 값을 얻어둠.
    private Map<String, Object> checkRefreshToken(String refreshToken)throws RefreshTokenException{

        try {
            Map<String, Object> values = jwtUtil.validateToken(refreshToken);

            return values;

        }catch(ExpiredJwtException expiredJwtException){
            throw new RefreshTokenException(RefreshTokenException.ErrorCase.OLD_REFRESH);
        }catch(Exception exception){
            exception.printStackTrace();
            new RefreshTokenException(RefreshTokenException.ErrorCase.NO_REFRESH);
        }
        return null;
    }

    // 832 추가
    private void sendTokens(String accessTokenValue, String refreshTokenValue, HttpServletResponse response) {


        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Gson gson = new Gson();

        String jsonStr = gson.toJson(Map.of("accessToken", accessTokenValue,
                "refreshToken", refreshTokenValue));

        try {
            response.getWriter().println(jsonStr);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
