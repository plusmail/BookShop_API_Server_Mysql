package com.bookshop.utils;

import lombok.Getter;
import lombok.ToString;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;

@Getter
@ToString
public class RequestTest202008 {
    @NotEmpty(message = "name은 필수입니다")
    private String name;
    @Min(value = 10, message = "age는 10살 이상부터 가능합니다")
    private int age;
}