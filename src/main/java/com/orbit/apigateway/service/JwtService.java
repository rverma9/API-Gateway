package com.orbit.apigateway.service;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

import com.orbit.apigateway.dto.UserResponseDto;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	
	private final String SECRET="mysecretkeymysecretkeymysecretkey12345"; // secret key customized
	private final Set<String> loggedOutTokens = new HashSet<>();
	
	//This will return the encoded key 
	private SecretKey getKey() {
		return Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
	}
	
	// This will generate Token for the first time request sent by the client with the username
	public String generateToken(UserResponseDto user) {
		
		return Jwts.builder().subject(user.getName())
							.claim("userId", String.valueOf(user.getId()))
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
	
	public String extractUserId(String token) {
		Object userId = Jwts.parser().verifyWith(getKey())
	            .build()
	            .parseSignedClaims(token)
	            .getPayload()
	            .get("userId");
		
		return userId != null ? String.valueOf(userId) : null;
	}
	
	public void blacklistToken(String token) {
		loggedOutTokens.add(token);
	}
	
	public boolean isTokenBlacklisted(String token) {
		return loggedOutTokens.contains(token);
	}
	
	// This will only validate the given Token
		public boolean validateToken(String token) {
			
			try {
				if (isTokenBlacklisted(token)) {
		            return false;
		        }
				Jwts.parser().verifyWith(getKey()).build().parseSignedClaims(token);
				return true;
			}
			catch(Exception e) {
				return false;
			}
		}
}
