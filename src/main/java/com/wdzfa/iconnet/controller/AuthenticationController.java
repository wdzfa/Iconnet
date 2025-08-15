package com.wdzfa.iconnet.controller;

import com.wdzfa.iconnet.dto.LoginRequestDto;
import com.wdzfa.iconnet.dto.RegisterRequestDto;
import com.wdzfa.iconnet.dto.ResponseData;
import com.wdzfa.iconnet.model.User;
import com.wdzfa.iconnet.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authService;

    @PostMapping("/register")
    public ResponseEntity<ResponseData<User>> register(@RequestBody RegisterRequestDto request) {
        ResponseData<User> response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<ResponseData<String>> login(@RequestBody LoginRequestDto request) {
        ResponseData<String> response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/validate-token")
    public ResponseEntity<ResponseData<Map<String, String>>> validateToken(@RequestParam String accessToken) {
        ResponseData<Map<String, String>> response = authService.validateAccessToken(accessToken);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<ResponseData<String>> refreshToken(@RequestBody LoginRequestDto request) {
        ResponseData<String> response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<ResponseData<Void>> logout(@RequestParam String accessToken) {
        ResponseData<Void> response = authService.logout(accessToken);
        return ResponseEntity.ok(response);
    }

}
