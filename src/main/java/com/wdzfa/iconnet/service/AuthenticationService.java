package com.wdzfa.iconnet.service;

import com.wdzfa.iconnet.dto.LoginRequestDto;
import com.wdzfa.iconnet.dto.RegisterRequestDto;
import com.wdzfa.iconnet.dto.ResponseData;
import com.wdzfa.iconnet.model.User;
import com.wdzfa.iconnet.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthenticationService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public ResponseData<User> register(RegisterRequestDto request) {
        ResponseData<User> response = new ResponseData<>();
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            response.setStatus(false);
            response.getMessages().add("Email sudah terdaftar");
            return response;
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepository.save(user);

        response.setStatus(true);
        response.getMessages().add("Registrasi berhasil");
        return response;
    }

    public ResponseData<String> login(LoginRequestDto request) {
        ResponseData<String> response = new ResponseData<>();

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
        } catch (Exception ex) {
            response.setStatus(false);
            response.getMessages().add("Email atau password salah");
            return response;
        }

        User user = userRepository.findByEmail(request.getEmail())
                .orElse(null);

        if (user == null) {
            response.setStatus(false);
            response.getMessages().add("User tidak ditemukan setelah autentikasi");
            return response;
        }

        String accessToken = jwtService.generateAccessToken(user.getEmail());
        user.setRefreshToken(accessToken);
        userRepository.save(user);

        response.setStatus(true);
        response.getMessages().add("Login berhasil");
        response.setPayload(accessToken);
        return response;
    }

    public ResponseData<Map<String, String>> validateAccessToken(String accessToken) {
        ResponseData<Map<String, String>> response = new ResponseData<>();
        Map<String, String> result = new HashMap<>();

        String email = jwtService.validateToken(accessToken);
        if (email == null) {
            response.setStatus(false);
            response.getMessages().add("Access token tidak valid");
            return response;
        }

        Date issuedAt = jwtService.getIssuedAt(accessToken);
        if (issuedAt == null) {
            response.setStatus(false);
            response.getMessages().add("Token tidak memiliki informasi issuedAt");
            return response;
        }

        long ageMillis = System.currentTimeMillis() - issuedAt.getTime();
        long ageMinutes = ageMillis / 1000 / 60;

        if (ageMinutes >= 1) {
            result.put("status", "EXPIRED");
            result.put("message", "Access token sudah lebih dari 1 menit, silakan refresh token");
            response.setStatus(false);
            response.getMessages().add("Token sudah kadaluarsa");
        } else {
            result.put("status", "VALID");
            result.put("message", "Access token masih berlaku");
            result.put("email", email);
            response.setStatus(true);
            response.getMessages().add("Token valid");
        }
        response.setPayload(result);
        return response;
    }

    public ResponseData<String> refreshToken(LoginRequestDto request) {
        ResponseData<String> response = new ResponseData<>();

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
            );
        } catch (Exception ex) {
            response.setStatus(false);
            response.getMessages().add("Email atau password salah");
            return response;
        }

        User user = userRepository.findByEmail(request.getEmail()).orElse(null);
        if (user == null) {
            response.setStatus(false);
            response.getMessages().add("User tidak ditemukan");
            return response;
        }

        if (user.getRefreshToken() != null) {
            ResponseData<Map<String, String>> validationResult = validateAccessToken(user.getRefreshToken());
            if (validationResult.isStatus() &&
                    "VALID".equals(validationResult.getPayload().get("status"))) {

                response.setStatus(true);
                response.getMessages().add("Token lama masih berlaku, tidak perlu refresh.");
                response.setPayload(user.getRefreshToken());
                return response;
            }
        }

        String refreshToken = jwtService.generateRefreshToken(user.getEmail());
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        response.setStatus(true);
        response.getMessages().add("Refresh token berhasil dibuat");
        response.setPayload(refreshToken);
        return response;
    }


    public ResponseData<Void> logout(String accessToken) {
        ResponseData<Void> response = new ResponseData<>();

        ResponseData<Map<String, String>> validationResult = validateAccessToken(accessToken);

        if (!validationResult.isStatus() || !"VALID".equals(validationResult.getPayload().get("status"))) {
            response.setStatus(false);
            response.getMessages().add("Access token tidak valid");
            return response;
        }

        User user = userRepository.findByRefreshToken(accessToken);
        if (user == null) {
            response.setStatus(false);
            response.getMessages().add("User tidak ditemukan untuk token ini");
            return response;
        }

        user.setRefreshToken(null);
        userRepository.save(user);

        response.setStatus(true);
        response.getMessages().add("Logout berhasil, token dihapus");
        return response;
    }

}
