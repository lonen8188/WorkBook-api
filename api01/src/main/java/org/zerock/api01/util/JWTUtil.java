package org.zerock.api01.util;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
@Log4j2
public class JWTUtil {
    // JWT는 인코딩 된 문자열
    // 헤더.페이로드.서명 으로 작성 되어 있음.
    // 클레임(claim)이라고 부르는 k/v로 구성된 정보들을 저장함
    // https://jwt.io 에서 테스트 가능
    // 마지막 서명부분에 비밀키를 지정해서 인코딩 함.
    @Value("${org.zerock.jwt.secret}")
    private String key;

    public String generateToken(Map<String, Object> valueMap, int days){  // JWT 문자열 생성용

        log.info("generateKey..." + key);

        // 799 추가 헤더 부분
        Map<String, Object> headers = new HashMap<>();
        headers.put("typ","JWT");
        headers.put("alg","HS256");

        // payload 부분 설정
        Map<String, Object> payloads = new HashMap<>();
        payloads.putAll(valueMap);

        // 테스트 시에는 짧은 유효 기간
        // 803 제거 int time = (1) * days; //테스트는 분단위로 나중에 60*24 (일)단위변경

        //10분 단위로 조정
        int time = (60*24) * days; //테스트는 분단위로 나중에 60*24 (일)단위변경

        Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256); // signWith Deprecated 임 키 생성후 전달

        String jwtStr = Jwts.builder()  // 799 추가
                .setHeader(headers)
                .setClaims(payloads)
                .setIssuedAt(Date.from(ZonedDateTime.now().toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(time).toInstant()))
                // Deprecated .signWith(SignatureAlgorithm.HS256, key.getBytes())
                .signWith(key)  // 24.04월 부로 변경
                .compact();

        // generateKey...hello1234567890hello1234567890hello1234567890
        // 2024-04-17T13:17:08.979+09:00  INFO 3608 --- [    Test worker] org.zerock.api01.util.JWTUtilTests       : eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJBQkNERSIsImlhdCI6MTcxMzMyNzQyOCwiZXhwIjoxNzEzMzI3NDg4fQ.r1kQqFoddqa9Q9lzPQmlIr_YcQuxEYFwjhhdABEmLyw
        // https://jwt.io 에서 테스트 가능
        return jwtStr;
        //return null;
    }


    public Map<String, Object> validateToken(String token)throws JwtException {  // 토큰 검증용
        // 문자열자체 구성이 잘못되거나, 유효기간, 서명에 문제 있는 등 처리용
        Map<String, Object> claim = null;

// Deprecated     claim = Jwts.parser()
//                .setSigningKey(key.getBytes()) // Set Key
//                .parseClaimsJws(token) // 파싱 및 검증, 실패 시 에러
//                .getBody();

        claim = Jwts.parserBuilder()
                .setSigningKey(key.getBytes()) // Set Key
                .build()
                .parseClaimsJws(token) // 파싱 및 검증, 실패 시 에러
                .getBody();

        return claim;
    }

}