package org.zerock.api01.util;

import lombok.extern.log4j.Log4j2;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Map;

@SpringBootTest
@Log4j2
public class JWTUtilTests {

    @Autowired
    private JWTUtil jwtUtil;

    @Test
    public void testGenerate() {
        // application.properties에 설정된 비밀키 정상 로딩 확인용
        Map<String, Object> claimMap = Map.of("mid","ABCDE");

        String jwtStr = jwtUtil.generateToken(claimMap,1);  // 1일 짜리 토큰 발행

        log.info(jwtStr);
//        Started JWTUtilTests in 16.691 seconds (process running for 21.252)
//        2024-04-17T13:12:40.500+09:00  INFO 9512 --- [    Test worker] org.zerock.api01.util.JWTUtil            : generateKey...hello1234567890hello1234567890hello1234567890
//        2024-04-17T13:12:40.501+09:00  INFO 9512 --- [    Test worker] org.zerock.api01.util.JWTUtilTests       : null
    }

    @Test // 802 추가
    public void testValidate() {

        //유효시간이 지난 토큰
//        String jwtStr = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJBQkNERSIsImlhdCI6MTcxMzMyNzQyOCwiZXhwIjoxNzEzMzI3NDg4fQ.r1kQqFoddqa9Q9lzPQmlIr_YcQuxEYFwjhhdABEmLyw";
//
//        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);
//
//        log.info(claim);

        // JWT expired at 2024-04-17T04:18:08Z. Current time: 2024-04-17T04:46:39Z, a difference of 1711571 milliseconds.  Allowed clock skew: 0 milliseconds.
        // io.jsonwebtoken.ExpiredJwtException: JWT expired at 2024-04-17T04:18:08Z. Current time: 2024-04-17T04:46:39Z, a difference of 1711571 milliseconds.  Allowed clock skew: 0 milliseconds

        // 토큰에 문자열 변조-추가
        String jwtStradd = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJBQkNERSIsImlhdCI6MTcxMzMyNzQyOCwiZXhwIjoxNzEzMzI3NDg4fQ.r1kQqFoddqa9Q9lzPQmlIr_YcQuxEYFwjhhdABEmLyw-add";

        Map<String, Object> claimadd = jwtUtil.validateToken(jwtStradd);

        log.info(claimadd);

        // JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.
        // io.jsonwebtoken.security.SignatureException: JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.

    }
//
    @Test  // 803 추가
    public void testAll() {

        String jwtStr = jwtUtil.generateToken(Map.of("mid","AAAA","email","aaaa@bbb.com"),1);

        log.info(jwtStr);

        Map<String, Object> claim = jwtUtil.validateToken(jwtStr);

        log.info("MID: " + claim.get("mid"));

        log.info("EMAIL: " + claim.get("email"));
        //generateKey...hello1234567890hello1234567890hello1234567890
        //2024-04-17T14:04:55.443+09:00  INFO 5796 --- [    Test worker] org.zerock.api01.util.JWTUtilTests       : eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJBQUFBIiwiZW1haWwiOiJhYWFhQGJiYi5jb20iLCJpYXQiOjE3MTMzMzAyOTUsImV4cCI6MTcxMzQxNjY5NX0.EpsQya0eF0KHH53HJ3b0YZoAeQdkVjvxP-Wv29I81PM
        //2024-04-17T14:04:55.502+09:00  INFO 5796 --- [    Test worker] org.zerock.api01.util.JWTUtilTests       : MID: AAAA
        //2024-04-17T14:04:55.503+09:00  INFO 5796 --- [    Test worker] org.zerock.api01.util.JWTUtilTests       : EMAIL: aaaa@bbb.com
    }

}
