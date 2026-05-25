package com.collectx.iam.dto;

import com.collectx.iam.entity.Role;
import com.collectx.iam.entity.UserStatus;
import lombok.Data;

@Data
public class UpdateUserRequestDTO {
    private String     name;
    private String     email;
    private Role       role;
    private UserStatus status;
    private String     password; // optional — null/blank means no change
    private String     phone;
}
