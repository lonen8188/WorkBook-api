package org.zerock.api01.service;

import jakarta.transaction.Transactional;
import org.zerock.api01.dto.PageRequestDTO;
import org.zerock.api01.dto.PageResponseDTO;
import org.zerock.api01.dto.TodoDTO;

@Transactional // import jakarta.transaction.Transactional
public interface TodoService {

    Long register(TodoDTO todoDTO);

    TodoDTO read(Long tno);


    PageResponseDTO<TodoDTO> list(PageRequestDTO pageRequestDTO); //867 추가

    void remove(Long tno); // 869 추가

    void modify(TodoDTO todoDTO); // 869 추가

}
