package com.orbit.apigateway.service;

import java.nio.charset.StandardCharsets;
import java.util.Date;

import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

import com.orbit.apigateway.dto.UserResponseDto;

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	private final String SECRET="mysecretkeymysecretkeymysecretkey12345"; // secret key customized
	
	//This will return the encoded key 
	private SecretKey getKey() {
		return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
	}
	
	// This will generate Token for the first time request sent by the client with the username
	public String generateToken(UserResponseDto user) {
		
		return Jwts.builder().subject(user.getName())
							.claim("userId", user.getId())
							.claim("role", user.getRole().name())
				             .issuedAt(new Date())
				             .expiration(new Date(System.currentTimeMillis() + 10*60*1000))
				             .signWith(getKey()).compact();
	}
	
	//This will extract and return the username by passing the token to the server
	public String extractUsername(String token) {
		
		return Jwts.parser().verifyWith(getKey())
				            .build()
				            .parseSignedClaims(token)
				            .getPayload().getSubject();
	}

	public String extractRole(String token) {
		return Jwts.parser().verifyWith(getKey())
	            .build()
	            .parseSignedClaims(token)
	            .getPayload().get("role",String.class);
	}
	
	public Long extractUserId(String token) {
		return Jwts.parser().verifyWith(getKey())
	            .build()
	            .parseSignedClaims(token)
	            .getPayload().get("userId",Long.class);
	}
	
	// This will only validate the given Token
		public boolean validateToken(String token) {
			
			try {
				Jwts.parser().verifyWith(getKey()).build().parseSignedClaims(token);
				return true;
			}
			catch(Exception e) {
				return false;
			}
		}
}
