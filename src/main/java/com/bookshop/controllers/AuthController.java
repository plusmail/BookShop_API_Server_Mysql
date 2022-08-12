package com.bookshop.controllers;

import com.aventrix.jnanoid.jnanoid.NanoIdUtils;
import com.bookshop.base.BaseController;
import com.bookshop.dao.User;
import com.bookshop.dto.SignUpDTO;
import com.bookshop.dto.UserResetPasswordDTO;
import com.bookshop.exceptions.AppException;
import com.bookshop.exceptions.NotFoundException;
import com.bookshop.models.AuthenticationRequest;
import com.bookshop.models.AuthenticationResponse;
import com.bookshop.services.MailService;
import com.bookshop.services.MyUserDetailsService;
import com.bookshop.services.UserService;
import com.bookshop.utils.JwtUtil;
import com.bookshop.utils.RequestTest202008;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.thymeleaf.context.Context;
import org.thymeleaf.spring5.SpringTemplateEngine;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.security.AuthProvider;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

@RestController
@RequestMapping("/api/auth")
@Log4j2
public class AuthController extends BaseController<Object> {
    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    @Autowired
    private MyUserDetailsService myUserDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private MailService mailService;

    @Autowired
    private SpringTemplateEngine templateEngine;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestHeader Map<String, Object> requestHeader, @RequestBody AuthenticationRequest authenticationRequest) {
        System.out.println("get header name ================" +requestHeader.toString());
        System.out.println("request =*********************** " + requestHeader.get("cookie"));
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    authenticationRequest.getUsername(), authenticationRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new AppException("Incorrect username or password");
        }
        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(authenticationRequest.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);
        User user = userService.findByUsername(authenticationRequest.getUsername());
        return this.resSuccess(new AuthenticationResponse(jwt, user));
    }

    @DeleteMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody Map<String, String> m) {
        String username = null;
        String accessToken = m.get("accessToken");
        try {
            username = jwtUtil.extractUsername(accessToken);
        } catch (IllegalArgumentException e) {} catch (ExpiredJwtException e) { //expire됐을 때
            username = e.getClaims().getSubject();
            log.info("username from expired access token: " + username);
        }

        try {
            if (redisTemplate.opsForValue().get(username) != null) {
                //delete refresh token
                redisTemplate.delete(username);
            }
        } catch (IllegalArgumentException e) {
            log.warn("user does not exist");
        }

        //cache logout token for 10 minutes!
        log.info(" logout ing : " + accessToken);
        redisTemplate.opsForValue().set(accessToken, true);
        redisTemplate.expire(accessToken, 10*6*1000, TimeUnit.MILLISECONDS);

        return new ResponseEntity(HttpStatus.OK);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody @Valid SignUpDTO signUpDTO) {
        User oldUser = userService.findByUsername(signUpDTO.getUsername());
        if (oldUser != null) {
            throw new AppException("Username has already exists");
        }
        User newUser = userService.create(signUpDTO);

        final UserDetails userDetails = myUserDetailsService.loadUserByUsername(newUser.getUsername());
        final String jwt = jwtUtil.generateToken(userDetails);
        return this.resSuccess(new AuthenticationResponse(jwt, newUser));
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestBody AuthenticationResponse authenticationResponse) {
        try {
            String jwt = authenticationResponse.getJwt();
            System.out.println("jwt:" + jwt);
            String username = jwtUtil.extractUsername(jwt);
            UserDetails userDetails = myUserDetailsService.loadUserByUsername(username);
            if (jwtUtil.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
            User user = userService.findByUsername(username);
            return this.resSuccess(new AuthenticationResponse(jwtUtil.generateToken(userDetails), user));
        } catch (Exception e) {
            throw new AppException(e.getMessage());
        }
    }

    @PostMapping("/check")
    public Map<String, Object> checker(@RequestHeader Map<String, Object> requestHeader, @RequestBody Map<String, String> m) {

        String username = null;
        String accessToken = m.get("accessToken");

        Map<String, Object> map = new HashMap<>();
        System.out.println("check =***********************1 " + m);
        try {
            System.out.println("check =***********************2 " + m.get("accessToken"));
            username = jwtUtil.extractUsername(m.get("accessToken"));
            System.out.println("check =***********************3 " + username);
        } catch (IllegalArgumentException e) {
            log.warn("Unable to get JWT Token");
        } catch (ExpiredJwtException e) {}
        if (username != null) {
            map.put("meta", true);
            map.put("_id", true);
            map.put("username", username);

        } else {
            map.put("success", false);
        }
        System.out.println("check =*********************** " + map);

        return map;
    }

    @DeleteMapping("/password")
    public ResponseEntity<?> resetPassword(@RequestBody @Valid UserResetPasswordDTO userResetPasswordDTO, HttpServletRequest request) {
        User user = userService.findByUsername(userResetPasswordDTO.getUsername());

        if (user == null) {
            throw new NotFoundException("Not found user with username");
        }

        String userAgent = request.getHeader("User-Agent");
        String time = new Date().toString();
        String newPassword = NanoIdUtils.randomNanoId(NanoIdUtils.DEFAULT_NUMBER_GENERATOR, NanoIdUtils.DEFAULT_ALPHABET, 15);

        Context context = new Context();
        context.setVariable("userAgent", userAgent);
        context.setVariable("time", time);
        context.setVariable("password", newPassword);
        String html = templateEngine.process("password-changed-email.html", context);

        ExecutorService service = Executors.newFixedThreadPool(2);
        service.submit(() -> {
            try {
                mailService.send("Thay đổi mật khẩu", html, user.getEmail(), true);

                user.setPassword(passwordEncoder.encode(newPassword));

                userService.update(user);
            } catch (MessagingException ignored) {
            }
        });

        return this.resSuccess("We have sent a new password to your email address, please check your inbox");
    }

}
