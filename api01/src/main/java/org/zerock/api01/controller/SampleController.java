package org.zerock.api01.controller;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/sample")  //http://localhost:8080/api/sample
public class SampleController {

    @GetMapping("/doA")  // http://localhost:8080/api/sample/doA
    //@PreAuthorize("hasRole('ROLE_USER')")  // USER 인가
    public List<String> doA() {
        return Arrays.asList("AAA","BBB","CCC");
    }

    
    @GetMapping("/doB") //http://localhost:8080/api/sample/doA
    //@PreAuthorize("hasRole('ROLE_ADMIN')")  // ADMIN 인가
    public List<String> doB() {
        return Arrays.asList("AdminAAA","AdminBBB","AdminCCC");
    }

}
