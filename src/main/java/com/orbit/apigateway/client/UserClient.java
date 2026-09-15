package com.orbit.apigateway.client;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.orbit.apigateway.dto.LoginRequestDto;
import com.orbit.apigateway.dto.UserResponseDto;

@FeignClient(name = "user-service")
public interface UserClient {

	@PostMapping("/api/users/login")
    UserResponseDto login(@RequestBody LoginRequestDto request);
}
