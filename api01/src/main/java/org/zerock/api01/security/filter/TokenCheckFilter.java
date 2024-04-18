package org.zerock.api01.security.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.api01.security.APIUserDetailsService;
import org.zerock.api01.security.exception.AccessTokenException;
import org.zerock.api01.util.JWTUtil;

import java.io.IOException;
import java.util.Map;

@Log4j2
@RequiredArgsConstructor
public class TokenCheckFilter extends OncePerRequestFilter {
    // AccessToken 검증 필터 토큰을 검사하고 문제가 없을 때만 접근 가능하도록 구성 하려 함.
    // 현재 사용자가 로그인한 사용자인지 체크하는 로그인 체크용 필터와 유사하게 JWT 토큰을 검사하는 역할을 위함.
    // extends OncePerRequestFilter : 하나의 요청에 대해서 한번씩 동작하는 필터 (서블릿 API 필터와 유사함)

    private final JWTUtil jwtUtil;  // 809 설정

    private final APIUserDetailsService apiUserDetailsService ; // 872 추가
    // JWT 기반의 인증 작업은 일반적인 세션 기반의 인증과 다름 @PerAuthorize를 이용 못함
    // CSRF 토큰 사용하지 않는 경우가 많음, CustomSecurityConfig 설정과 같이 세션을 생성하지 않고, 기존에 만들어진 세션을 사용하지 않음. STATELESS
    // JWT 인증을 이용하는 username-> mid 이용해서 인증 정보를 직접 처리해서 시큐리티에서 활용할 수  있도록 지정
    // SecurityContextHolder라는 객체로 인증과 관련된 정보를 저장해서 컨트롤러등에 활용함. -> @PerAuthorize 사용가능 해짐.


    @Override  // 809 설정
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();


        if (!path.startsWith("/api/")) {
            filterChain.doFilter(request, response);
            return;
        }

        log.info("Token Check Filter..........................");
        log.info("JWTUtil: " + jwtUtil);

//   874제거      try {
//            validateAccessToken(request);
//            filterChain.doFilter(request, response); // // 814 try 문으로 이동
//        }catch (AccessTokenException accessTokenException){
//            accessTokenException.sendResponseError(response);
//        }
        // TokenCheckFilter 의 설정은 CustomSecurityConfig를 이용함


        try{  // 874 추가  jwt의 mid 값을 이용해서 UserDetails를 구하고 UsernamePasswordAuthenticationToken 객체를 구성함

            Map<String, Object> payload = validateAccessToken(request);

            //mid
            String mid = (String)payload.get("mid");

            log.info("mid: " + mid);

            UserDetails userDetails = apiUserDetailsService.loadUserByUsername(mid);
            // JWT 인증을 이용하는 username-> mid 이용해서 인증 정보를 직접 처리해서 시큐리티에서 활용할 수  있도록 지정

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());


            SecurityContextHolder.getContext().setAuthentication(authentication);
            // SecurityContextHolder라는 객체로 인증과 관련된 정보를 저장해서 컨트롤러등에 활용함. -> @PerAuthorize 사용가능 해짐.
            filterChain.doFilter(request,response);

        }catch(AccessTokenException accessTokenException){
            accessTokenException.sendResponseError(response);
        }


    }

    //  812 추가 토큰 예외 처리
    private Map<String, Object> validateAccessToken(HttpServletRequest request) throws AccessTokenException {

        String headerStr = request.getHeader("Authorization");

        if(headerStr == null  || headerStr.length() < 8){
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.UNACCEPT);
        }

        //Bearer 생략
        String tokenType = headerStr.substring(0,6);
        String tokenStr =  headerStr.substring(7);

        if(tokenType.equalsIgnoreCase("Bearer") == false){
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADTYPE);
        }

        log.info("TOKENSTR-----------------------------");
        log.info(tokenStr);
        log.info("----------------------------------------");

        try{
            Map<String, Object> values = jwtUtil.validateToken(tokenStr);

            return values;
        }catch(MalformedJwtException malformedJwtException){
            log.error("MalformedJwtException----------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.MALFORM);
        }catch(SignatureException signatureException){
            log.error("SignatureException----------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.BADSIGN);
        }catch(ExpiredJwtException expiredJwtException){
            log.error("ExpiredJwtException----------------------");
            throw new AccessTokenException(AccessTokenException.TOKEN_ERROR.EXPIRED);
        }
    }




}
