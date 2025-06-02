package com.uds.project.service_authentification_compte.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.uds.project.service_authentification_compte.configuration.JwtUtils;
import com.uds.project.service_authentification_compte.entity.RegisterDto;
import com.uds.project.service_authentification_compte.entity.Role;
import com.uds.project.service_authentification_compte.entity.User;
import com.uds.project.service_authentification_compte.repository.RoleRepository;
import com.uds.project.service_authentification_compte.repository.UserRepository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;


@SpringBootTest
@AutoConfigureMockMvc
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserRepository userRepository;

    @MockBean
    private RoleRepository roleRepository;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @MockBean
    private JwtUtils jwtUtils;

    @MockBean
    private AuthenticationManager authenticationManager;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    public void testLoginSuccess() throws Exception {
        User loginUser = new User();
        loginUser.setUsername("testuser");
        loginUser.setPassword("password");

        Authentication auth = new UsernamePasswordAuthenticationToken("testuser", "password");
        when(authenticationManager.authenticate(any())).thenReturn(auth);

        when(jwtUtils.generateToken("testuser")).thenReturn("fake-jwt-token");

        mockMvc.perform(post("/api/user/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginUser)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").value("fake-jwt-token"))
            .andExpect(jsonPath("$.type").value("Bearer"));
    }

    @Test
    public void testLoginFail() throws Exception {
        User loginUser = new User();
        loginUser.setUsername("baduser");
        loginUser.setPassword("badpassword");

        // Simule une exception d'authentification
        when(authenticationManager.authenticate(any()))
            .thenThrow(new RuntimeException("Bad credentials"));

        mockMvc.perform(post("/api/user/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginUser)))
            .andExpect(status().isUnauthorized())
            .andExpect(content().string("Invalid Username or Password"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void testRegisterSuccess() throws Exception {
        RegisterDto registerDto = new RegisterDto();
        registerDto.setUsername("newuser");
        registerDto.setPassword("newpassword");
        Set<String> roles = new HashSet<>();
        roles.add("ADMIN");
        registerDto.setRoleNames(roles);

        when(userRepository.findByUsername("newuser")).thenReturn(null);

        Role adminRole = new Role();
        adminRole.setName("ADMIN");
        when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));


        when(passwordEncoder.encode("newpassword")).thenReturn("encodedPassword");

        User savedUser = new User();
        savedUser.setUsername("newuser");
        savedUser.setPassword("encodedPassword");
        savedUser.setRoles(Set.of(adminRole));
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        mockMvc.perform(post("/api/user/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerDto)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.username").value("newuser"))
            .andExpect(jsonPath("$.roleNames[0]").value("ADMIN"));
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void testRegisterUsernameExists() throws Exception {
        RegisterDto registerDto = new RegisterDto();
        registerDto.setUsername("existinguser");
        registerDto.setPassword("pass");
        registerDto.setRoleNames(Set.of("ADMIN"));

  
        User existingUser = new User();
        existingUser.setUsername("existinguser");
        when(userRepository.findByUsername("existinguser")).thenReturn(existingUser);

        mockMvc.perform(post("/api/user/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerDto)))
            .andExpect(status().isBadRequest())
            .andExpect(content().string("Username already exists"));
    }

    @Test
    @WithMockUser(username = "user", roles = "USER")
    public void testRegisterForbiddenForNonAdmin() throws Exception {
        RegisterDto registerDto = new RegisterDto();
        registerDto.setUsername("testuser");
        registerDto.setPassword("password");
        registerDto.setRoleNames(Set.of("USER"));

        mockMvc.perform(post("/api/user/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerDto)))
            .andExpect(status().isForbidden());
    }
    
    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    public void testRegisterWithInvalidRole() throws Exception {
        RegisterDto registerDto = new RegisterDto();
        registerDto.setUsername("newuser2");
        registerDto.setPassword("password");
        registerDto.setRoleNames(Set.of("INVALID_ROLE"));

        when(userRepository.findByUsername("newuser2")).thenReturn(null);
        when(roleRepository.findByName("INVALID_ROLE")).thenReturn(Optional.empty());

        mockMvc.perform(post("/api/user/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(registerDto)))
            .andExpect(status().isInternalServerError())
            .andExpect(content().string(org.hamcrest.Matchers.containsString("Role not found")));
    }
}