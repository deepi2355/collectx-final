package com.collectx.iam.controller;

import com.collectx.iam.dto.RegisterRequestDTO;
import com.collectx.iam.dto.UpdateUserRequestDTO;
import com.collectx.iam.dto.UserResponseDTO;
import com.collectx.iam.entity.AuditLog;
import com.collectx.iam.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AuthService authService;

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/users")
    public UserResponseDTO createUser(@RequestBody RegisterRequestDTO dto) {
        return authService.createUser(dto);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public List<UserResponseDTO> getAllUsers() {
        return authService.getAllUsers();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PutMapping("/users/{id}")
    public UserResponseDTO updateUser(@PathVariable Long id, @RequestBody UpdateUserRequestDTO dto) {
        return authService.updateUser(id, dto);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{id}")
    public String deleteUser(@PathVariable Long id) {
        return authService.deleteUser(id);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/audit-logs")
    public List<AuditLog> getAuditLogs() {
        return authService.getAllAuditLogs();
    }
}
