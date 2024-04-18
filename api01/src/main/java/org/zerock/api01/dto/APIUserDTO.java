package org.zerock.api01.dto;
import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;


@Getter
@Setter
@ToString
public class APIUserDTO extends User {  // 엔티티에서 받은 정보를 dto로 변환

    private String mid;
    private String mpw;

    public APIUserDTO(String username, String password, Collection<GrantedAuthority> authorities) {  // 권한 Collection<GrantedAuthority> authorities
        super(username, password, authorities);
        this.mid = username;
        this.mpw = password;
    }
}
