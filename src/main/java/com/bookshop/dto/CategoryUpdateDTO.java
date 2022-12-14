package com.bookshop.dto;

import com.bookshop.constants.Common;
import com.bookshop.validators.NullOrNotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class CategoryUpdateDTO {

    @NullOrNotEmpty(message = "is invalid")
    @Length(max = Common.STRING_LENGTH_LIMIT)
    private String name;

    @Length(max = 100000)
    private String description;

    private Boolean isAuthor;

    private Long parentCategoryId;
}
