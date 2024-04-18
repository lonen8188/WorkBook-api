package org.zerock.api01.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Controller;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@EnableWebMvc
public class CustomServletConfig implements WebMvcConfigurer {

//    @Override // static폴더 제외 처리
//    public void addResourceHandlers(ResourceHandlerRegistry registry) {
//
//        registry.addResourceHandler("/js/**")
//                .addResourceLocations("classpath:/static/js/");
//        registry.addResourceHandler("/fonts/**")
//                .addResourceLocations("classpath:/static/fonts/");
//        registry.addResourceHandler("/css/**")
//                .addResourceLocations("classpath:/static/css/");
//        registry.addResourceHandler("/assets/**").
//                addResourceLocations("classpath:/static/assets/");
//
//    }

    // 777 static 폴더 html 타입리프 대체용
    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry){
        registry.addResourceHandler("/files/**").addResourceLocations("classpath:/static/");
    }  //http://localhost:8080/files/sample.html 보인다

}
