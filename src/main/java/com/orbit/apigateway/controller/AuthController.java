package com.orbit.apigateway.controller;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.orbit.apigateway.client.UserClient;
import com.orbit.apigateway.dto.LoginRequestDto;
import com.orbit.apigateway.dto.UserResponseDto;
import com.orbit.apigateway.service.JwtService;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	private final JwtService jwtService;
	private final UserClient userClient;
	
	public AuthController(JwtService jwtService, UserClient userClient)
	{
		this.jwtService = jwtService;
		this.userClient = userClient;
	}
	
	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody LoginRequestDto request){
		UserResponseDto user = userClient.login(request);
		String token = jwtService.generateToken(user);
		return ResponseEntity.ok(token);
	}
	
	@PostMapping("/logout")
	public ResponseEntity<String> logout(@RequestHeader ("Authorization") String authorization){
		String token = authorization.substring(7).trim();
		jwtService.blacklistToken(token);
		return ResponseEntity.ok("Logout successful");
	}
	
	@GetMapping("/me")
	public ResponseEntity<Map<String,Object>> me(@RequestHeader ("Authorization") String authorization) {
		
		String token = authorization.substring(7).trim();
		Map<String,Object> response = new HashMap<>();
		
		response.put("username", jwtService.extractUsername(token));
		response.put("role", jwtService.extractRole(token));
		response.put("userId", jwtService.extractUserId(token));
		return ResponseEntity.ok(response);
	}
}

