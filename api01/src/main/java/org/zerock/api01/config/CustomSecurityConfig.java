package org.zerock.api01.config;


import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.zerock.api01.security.APIUserDetailsService;
import org.zerock.api01.security.filter.APILoginFilter;
import org.zerock.api01.security.filter.RefreshTokenFilter;
import org.zerock.api01.security.filter.TokenCheckFilter;
import org.zerock.api01.security.handler.APILoginSuccessHandler;
import org.zerock.api01.util.JWTUtil;


import javax.sql.DataSource;
import java.util.Arrays;

@Configuration
@Log4j2
@EnableMethodSecurity
@RequiredArgsConstructor
public class CustomSecurityConfig {

    private final APIUserDetailsService apiUserDetailsService; // 786 추가

    private final JWTUtil jwtUtil; // 806 추가 토큰 발행용

//    private final DataSource dataSource;
//
//    private final UserDetailsService userDetailsService;

//    @Bean
//    public UserDetailsService userDetailsService(){
//        return new CustomUserDetailsService(passwordEncoder());
//    }


    @Bean // 패스워드 암호화
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)throws Exception {

        log.info("----------------Security Config----------------------");

        //deprecated
        // http.formLogin();
        // http.formLogin(Customizer.withDefaults());
//        http.formLogin(form -> {
//
//            form.loginPage("/member/login");
//
//
//        });

        //787 추가 로그인 인증에 사용됨 AuthenticationManager설정
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(apiUserDetailsService).passwordEncoder(passwordEncoder());
        // Get AuthenticationManager
        AuthenticationManager authenticationManager = authenticationManagerBuilder.build();

        //반드시 필요
        http.authenticationManager(authenticationManager);

        //APILoginFilter  http://localhost/generateToken 으로 토큰 발행을 진행함. -> secutiry.filter.APILoginFilter 동작 함.
        APILoginFilter apiLoginFilter = new APILoginFilter("/generateToken");
        apiLoginFilter.setAuthenticationManager(authenticationManager);


        //APILoginSuccessHandler 793 추가 성공시 처리되는 핸들러
        APILoginSuccessHandler successHandler = new APILoginSuccessHandler(jwtUtil); // 806 매개값 jwtUtil추가
        // SuccessHandler 세팅 793 추가
        apiLoginFilter.setAuthenticationSuccessHandler(successHandler);

        // http://localhost:8080/files/apiLogin.html 호출 시 Authenticated user
        //2024-04-17T13:01:15.128+09:00 DEBUG 10128 --- [nio-8080-exec-1] o.z.a.security.filter.APILoginFilter     : Set SecurityContextHolder to UsernamePasswordAuthenticationToken [Principal=APIUserDTO(mid=apiuser10, mpw=$2a$10$0NFOrsC0tEhMcitpKvQTKeZRtr6BXvDcZ93WDNqtDiOZrowCdwN1u), Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[ROLE_USER]]
        //2024-04-17T13:01:15.128+09:00  INFO 10128 --- [nio-8080-exec-1] o.z.a.s.handler.APILoginSuccessHandler   : Login Success Handler................................

        // jwtUtil 추가 후 테스트 -> Network -> http://localhost:8080/generateToken
        // {
        //    "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJhcGl1c2VyMTAiLCJpYXQiOjE3MTMzMzA3NTUsImV4cCI6MTcxMzQxNzE1NX0.WiRbWLTZUn87ndEbI37iQNOPPp4_05-LJz9_gml4N4c",
        //    "refreshToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJtaWQiOiJhcGl1c2VyMTAiLCJpYXQiOjE3MTMzMzA3NTUsImV4cCI6MTcxNTkyMjc1NX0.Ajh4_snW_b6nUNEdu7o_tvTjGpQSL3C0pPwYUxE3RGA"
        //}
        //APILoginFilter의 위치 조정

        http.addFilterBefore(apiLoginFilter, UsernamePasswordAuthenticationFilter.class);

        // 809 추가 설정
        // api로 시작하는 모든 경로는 TokenCheckFilter 동작
        http.addFilterBefore(
                tokenCheckFilter(jwtUtil),  // 하단에 tokenCheckFilter 추가 필수 , apiUserDetailsService
                UsernamePasswordAuthenticationFilter.class

                //http://localhost:8080/api/sample/doA 요청시
                //Login Success Handler................................
                //2024-04-17T14:12:35.328+09:00  INFO 6452 --- [nio-8080-exec-3] o.z.a.s.handler.APILoginSuccessHandler   : UsernamePasswordAuthenticationToken [Principal=APIUserDTO(mid=apiuser10, mpw=$2a$10$0NFOrsC0tEhMcitpKvQTKeZRtr6BXvDcZ93WDNqtDiOZrowCdwN1u), Credentials=[PROTECTED], Authenticated=true, Details=null, Granted Authorities=[ROLE_USER]]
                //2024-04-17T14:12:35.328+09:00  INFO 6452 --- [nio-8080-exec-3] o.z.a.s.handler.APILoginSuccessHandler   : apiuser10
                //2024-04-17T14:12:35.329+09:00  INFO 6452 --- [nio-8080-exec-3] org.zerock.api01.util.JWTUtil            : generateKey...hello1234567890hello1234567890hello1234567890
                //2024-04-17T14:12:35.448+09:00  INFO 6452 --- [nio-8080-exec-3] org.zerock.api01.util.JWTUtil            : generateKey...hello1234567890hello1234567890hello1234567890
                //2024-04-17T14:38:36.720+09:00 DEBUG 6452 --- [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Securing GET /api/sample/doA
                //2024-04-17T14:38:36.721+09:00 DEBUG 6452 --- [nio-8080-exec-2] o.s.s.w.a.AnonymousAuthenticationFilter  : Set SecurityContextHolder to anonymous SecurityContext
                //2024-04-17T14:38:36.721+09:00 DEBUG 6452 --- [nio-8080-exec-2] o.s.security.web.FilterChainProxy        : Secured GET /api/sample/doA
        );

        // 821 refreshToken 호출 처리
        http.addFilterBefore(new RefreshTokenFilter("/refreshToken", jwtUtil),
                TokenCheckFilter.class);
        // http://localhost:8080/refreshToken 으로 발행 여부 파악
        // Securing GET /refreshToken
        // 2024-04-17T15:08:29.164+09:00  INFO 10424 --- [nio-8080-exec-2] o.z.a.s.filter.RefreshTokenFilter        : Refresh Token Filter...run..............1


        // 772 추가 설정
        http.csrf(httpSecurityCsrfConfigurer ->  httpSecurityCsrfConfigurer.disable() ); // csrf 토큰 비활성화
        http.sessionManagement(httpSecuritySessionManagementConfigurer -> {
            httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });  // 세션 사용하지 않음 jwt 활용

        // 850 추가 설정 -> 동일 서버출처 정책 (같은 서버가 아닌 곳에서 요청시 오류 발생 해결용)
        http.cors(httpSecurityCorsConfigurer -> {
            httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource());  // 하단에 객체 생성 메서드 필수
        });


//        http.logout(httpSecurityLogoutConfigurer -> httpSecurityLogoutConfigurer.logoutUrl("/logout"));
//
//        http.rememberMe(httpSecurityRememberMeConfigurer -> {
//
//            httpSecurityRememberMeConfigurer.key("12345678")
//                    .tokenRepository(persistentTokenRepository())
//                    .userDetailsService(userDetailsService)
//                    .tokenValiditySeconds(60*60*24*30);
//
//        });
//
//        http.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
//
//            httpSecurityExceptionHandlingConfigurer.accessDeniedHandler(accessDeniedHandler());
//        });
//
//        http.oauth2Login( httpSecurityOAuth2LoginConfigurer -> {
//            httpSecurityOAuth2LoginConfigurer.loginPage("/member/login");
//            httpSecurityOAuth2LoginConfigurer.successHandler(authenticationSuccessHandler());
//        });


        return http.build();
    }
//
//    @Bean
//    public AccessDeniedHandler accessDeniedHandler() {
//        return new Custom403Handler();
//    }
//
//
//    @Bean
//    public AuthenticationSuccessHandler authenticationSuccessHandler() {
//        return new CustomSocialLoginSuccessHandler(passwordEncoder());
//    }


    @Bean  // 정적 경로 제외
    public WebSecurityCustomizer webSecurityCustomizer() {

        log.info("------------web configure-------------------");

        return (web) -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());

    }

    // 810 추가
    private TokenCheckFilter tokenCheckFilter(JWTUtil jwtUtil){ // , APIUserDetailsService apiUserDetailsService
        return new TokenCheckFilter(jwtUtil); //apiUserDetailsService,
    }
//
//    @Bean
//    public PersistentTokenRepository persistentTokenRepository() {
//        JdbcTokenRepositoryImpl repo = new JdbcTokenRepositoryImpl();
//        repo.setDataSource(dataSource);
//        return repo;
//    }

    @Bean  // 850 추가 설정  -> 다른 서버에서 요청시 해결용 객체
    public CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("HEAD", "GET", "POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Cache-Control", "Content-Type"));
        configuration.setAllowCredentials(true);

        //setAllowedOrigins : 교차 출처 요청이 허용되는 출처 목록입니다.
        //setAllowedMethods : 허용할 HTTP 메소드 설정
        //setAllowedHeaders : 실제 요청 중에 사용이 허용되도록 사전 요청이 나열할 수 있는 헤더 목록을 설정.
        //setAllowedCredentials : 사용자 자격 증명이 지원되는지 여부

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

}
