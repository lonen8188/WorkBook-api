package org.zerock.api01.security.filter;


import com.google.gson.Gson;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.Map;

@Log4j2
public class APILoginFilter extends AbstractAuthenticationProcessingFilter {
    // extends AbstractAuthenticationProcessingFilter 인증 단계를 처리하고 인증에 성공 했을 때 AT, RT 를 발행 전송하려 함.
    // 생성자와 추상 메서드를 오버라이드 해야 함.

    public APILoginFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }  // 생성자

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        log.info("APILoginFilter-----------------------------------");
        // 789 추가 -> POST 방식으로 요청이 들어올 때 JSON 문자열 처리 parseRequestJSON 메서드 하단 구성
        if (request.getMethod().equalsIgnoreCase("GET")) {  //get메서드 제외
            log.info("GET METHOD NOT SUPPORT");
            return null;
        }
        log.info("-----------------------------------------");
        log.info(request.getMethod());

        Map<String, String> jsonData = parseRequestJSON(request);

        log.info("jsonData: "+jsonData);

        // 791 추가 db정보활용
        UsernamePasswordAuthenticationToken authenticationToken
                = new UsernamePasswordAuthenticationToken(
                jsonData.get("mid"),
                jsonData.get("mpw"));

        return getAuthenticationManager().authenticate(authenticationToken);

        //-----------------------------------------
        //2024-04-17T12:52:18.951+09:00  INFO 3284 --- [nio-8080-exec-3] o.z.a.security.filter.APILoginFilter     : POST
        //2024-04-17T12:52:18.951+09:00  INFO 3284 --- [nio-8080-exec-3] o.z.a.security.filter.APILoginFilter     : jsonData: {mid=apiuser10, mpw=1111}
        //Hibernate:
        //    select
        //        a1_0.mid,
        //        a1_0.mpw
        //    from
        //        apiuser a1_0
        //    where
        //        a1_0.mid=?
        //2024-04-17T12:52:19.252+09:00  INFO 3284 --- [nio-8080-exec-3] o.z.a.security.APIUserDetailsService     : APIUserDetailsService apiUser-------------------------------------
        //2024-04-17T12:52:19.256+09:00  INFO 3284 --- [nio-8080-exec-3] o.z.a.security.APIUserDetailsService     : APIUserDTO(mid=apiuser10, mpw=$2a$10$0NFOrsC0tEhMcitpKvQTKeZRtr6BXvDcZ93WDNqtDiOZrowCdwN1u)
        //2024-04-17T12:52:19.359+09:00 DEBUG 3284 --- [nio-8080-exec-3] o.s.s.a.dao.DaoAuthenticationProvider    : Authenticated user
        //2024-04-17T12:52:19.361+09:00 DEBUG 3284 --- [nio-8080-exec-3] o.z.a.security.filter.APILoginFilter     : Set SecurityContextHolder to UsernamePasswordAuthenticationToken [Principal=APIUserDTO(mid=apiuser10, mpw=$2a$10$0NFOrsC0tEhMcitpKvQTKeZRtr6BXvDcZ93WDNqtDiOZrowCdwN1u), Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[ROLE_USER]]
        // 791 제거 return null ;
    }

    // 789 추가
    private Map<String,String> parseRequestJSON(HttpServletRequest request) {

        //JSON 데이터를 분석해서 mid, mpw 전달 값을 Map으로 처리
        try(Reader reader = new InputStreamReader(request.getInputStream())){

            Gson gson = new Gson();

            return gson.fromJson(reader, Map.class);

        }catch(Exception e){
            log.error(e.getMessage());
        }
        return null;
    }

}
