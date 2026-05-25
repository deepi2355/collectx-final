package com.collectx.iam.service;

import com.collectx.iam.dto.AuthResponseDTO;
import com.collectx.iam.dto.RegisterRequestDTO;
import com.collectx.iam.dto.UpdateUserRequestDTO;
import com.collectx.iam.dto.UserResponseDTO;
import com.collectx.iam.entity.AuditLog;
import com.collectx.iam.entity.Role;
import com.collectx.iam.entity.User;
import com.collectx.iam.entity.UserStatus;
import com.collectx.iam.repository.AuditLogRepository;
import com.collectx.iam.repository.UserRepository;
import com.collectx.iam.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;   // ★ NEW: BCrypt encoder import
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;   // ★ NEW: injected BCrypt encoder from SecurityConfig


    private static final long EXPIRES_IN_SECONDS = 60 * 60 * 10;

    private static final int    MAX_FAILED_ATTEMPTS    = 5;
    private static final int    LOCK_DURATION_MINUTES  = 15;

    public String register(RegisterRequestDTO dto) {
        log.info("Registering new user email={} role={}", dto.getEmail(), dto.getRole());


        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new RuntimeException("Email already exists: " + dto.getEmail());
        }

        if (dto.getPassword() == null || dto.getPassword().length() < 8) {
            throw new RuntimeException("Password must be at least 8 characters");
        }

        User user = new User();

        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));  // ★ CHANGED: plain text → BCrypt hash
        user.setRole(dto.getRole());
        user.setStatus(UserStatus.ACTIVE);
        user.setPhone(dto.getPhone());
        userRepository.save(user);
        return "User Registered";
    }



    public UserResponseDTO createUser(RegisterRequestDTO dto) {
        log.info("Admin creating user email={} role={}", dto.getEmail(), dto.getRole());
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new RuntimeException("Email already exists: " + dto.getEmail());
        }
        if (dto.getPassword() == null || dto.getPassword().length() < 8) {
            throw new RuntimeException("Password must be at least 8 characters");
        }
        User user = new User();
        user.setName(dto.getName());
        user.setEmail(dto.getEmail());
        user.setPassword(passwordEncoder.encode(dto.getPassword()));  // ★ CHANGED: plain text → BCrypt hash
        user.setRole(dto.getRole());
        user.setStatus(UserStatus.ACTIVE);
        user.setPhone(dto.getPhone());
        UserResponseDTO result = toDTO(userRepository.save(user));
        saveAudit("system", "CREATE_USER", dto.getEmail(), "Created user role=" + dto.getRole());
        return result;
    }

    public List<UserResponseDTO> getAllUsers() {
        return userRepository.findAll().stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
    }

    public UserResponseDTO updateUser(Long userId, UpdateUserRequestDTO dto) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));
        if (dto.getName()   != null) user.setName(dto.getName());
        if (dto.getEmail()  != null) {
            if (!dto.getEmail().equals(user.getEmail()) && userRepository.existsByEmail(dto.getEmail())) {
                throw new RuntimeException("Email already exists: " + dto.getEmail());
            }
            user.setEmail(dto.getEmail());
        }
        if (dto.getRole()   != null) user.setRole(dto.getRole());
        if (dto.getStatus() != null) user.setStatus(dto.getStatus());
        if (dto.getPassword() != null && !dto.getPassword().isBlank()) {
            if (dto.getPassword().length() < 8) throw new RuntimeException("Password must be at least 8 characters");
            user.setPassword(passwordEncoder.encode(dto.getPassword()));  // ★ CHANGED: hash new password before saving
        }
        if (dto.getPhone() != null) user.setPhone(dto.getPhone());
        UserResponseDTO updated = toDTO(userRepository.save(user));
        saveAudit("system", "UPDATE_USER", user.getEmail(), "Updated user id=" + userId);
        return updated;
    }

    public String deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found: " + userId));
        String email = user.getEmail();
        userRepository.delete(user);
        saveAudit("system", "DELETE_USER", email, "Deleted user id=" + userId);
        return "User deleted";
    }

    private UserResponseDTO toDTO(User user) {
        return new UserResponseDTO(
                user.getUserId(),
                user.getName(),
                user.getEmail(),
                user.getRole().name(),
                user.getStatus().name(),
                user.getPhone()
        );
    }



    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    private void saveAudit(String performedBy, String action, String targetEmail, String details) {
        try {
            AuditLog entry = new AuditLog();
            entry.setPerformedBy(performedBy);
            entry.setAction(action);
            entry.setTargetEmail(targetEmail);
            entry.setDetails(details);
            entry.setCreatedAt(LocalDateTime.now());
            auditLogRepository.save(entry);
        } catch (Exception e) {
            // non-critical — never fail the main operation
            log.warn("Failed to save audit log: {}", e.getMessage());
        }
    }


    public List<Long> getAgentIds() {
        return userRepository.findByRole(Role.AGENT)
                .stream()
                .map(User::getUserId)
                .collect(Collectors.toList());
    }

    public AuthResponseDTO login(String email, String password) {
        log.info("Login attempt for email={}", email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));


        if (user.getLockedUntil() != null) {
            if (LocalDateTime.now().isBefore(user.getLockedUntil())) {
                long minutesLeft = java.time.Duration.between(LocalDateTime.now(), user.getLockedUntil()).toMinutes() + 1;
                saveAudit(email, "LOGIN_BLOCKED", email, "Account locked — " + minutesLeft + " min remaining");
                throw new RuntimeException("Account is locked. Try again in " + minutesLeft + " minute(s).");
            } else {
                // ★ NEW — Lock has expired: auto-unlock and reset counter
                user.setLockedUntil(null);
                user.setFailedAttempts(0);
                user.setStatus(UserStatus.ACTIVE);
                userRepository.save(user);
                log.info("Account auto-unlocked for email={}", email);
            }
        }


        boolean passwordMatches;
        String stored = user.getPassword();
        if (stored != null && stored.startsWith("$2a$")) {
            // Already BCrypt — use encoder
            passwordMatches = passwordEncoder.matches(password, stored);
        } else {
            // Legacy plain text — compare directly, auto-migrate on success
            passwordMatches = stored != null && stored.equals(password);
            if (passwordMatches) {
                log.info("Auto-migrating plain-text password to BCrypt for email={}", email);
                user.setPassword(passwordEncoder.encode(password));
                userRepository.save(user);
            }
        }

        if (!passwordMatches) {

            int attempts = user.getFailedAttempts() + 1;
            user.setFailedAttempts(attempts);

            if (attempts >= MAX_FAILED_ATTEMPTS) {

                user.setLockedUntil(LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES));
                user.setStatus(UserStatus.LOCKED);
                userRepository.save(user);
                saveAudit("system", "ACCOUNT_LOCKED", email,
                        "Locked after " + MAX_FAILED_ATTEMPTS + " failed attempts");
                log.warn("Account LOCKED for email={} after {} failed attempts", email, MAX_FAILED_ATTEMPTS);
                throw new RuntimeException(
                        "Account locked after " + MAX_FAILED_ATTEMPTS + " failed attempts. Try again in " + LOCK_DURATION_MINUTES + " minutes.");
            } else {
                // ★ NEW — Not yet at threshold: warn how many attempts remain
                userRepository.save(user);
                saveAudit("system", "LOGIN_FAILED", email,
                        "Invalid password — attempt " + attempts + "/" + MAX_FAILED_ATTEMPTS);
                log.warn("Failed login attempt {}/{} for email={}", attempts, MAX_FAILED_ATTEMPTS, email);
                throw new RuntimeException(
                        "Invalid credentials. " + (MAX_FAILED_ATTEMPTS - attempts) + " attempt(s) remaining before lockout.");
            }
        }


        if (user.getFailedAttempts() > 0 || user.getStatus() != UserStatus.ACTIVE) {
            user.setFailedAttempts(0);
            user.setLockedUntil(null);
            user.setStatus(UserStatus.ACTIVE);
            userRepository.save(user);
        }
        saveAudit(email, "LOGIN_SUCCESS", email, "Successful login");

        String token = jwtUtil.generateToken(user.getEmail(), user.getRole().name());
        return new AuthResponseDTO(token, user.getEmail(), user.getRole().name(), EXPIRES_IN_SECONDS);
    }
}
