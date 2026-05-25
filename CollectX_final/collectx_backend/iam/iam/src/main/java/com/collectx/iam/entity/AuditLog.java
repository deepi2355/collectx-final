package com.collectx.iam.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long logId;

    private String performedBy;   // email of admin who did the action
    private String action;        // CREATE_USER, UPDATE_USER, DELETE_USER
    private String targetEmail;   // email of the affected user
    private String details;       // free-text description

    private LocalDateTime createdAt;
}
