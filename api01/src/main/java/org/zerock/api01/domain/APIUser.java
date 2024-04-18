package org.zerock.api01.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.*;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
public class APIUser {  // Access Key 발급받을 때 자신의 id와 pw를 이용

    @Id // pk 설정
    private String mid;  // 회원  id
    private String mpw;  // 회원  pw

    public void changePw(String mpw){  // 암호 변경 
        this.mpw = mpw;
    }
}
