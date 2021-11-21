package com.jrock.springsecuritybasic.security.configs;

import com.jrock.springsecuritybasic.security.provider.CustomAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationDetailsSource authenticationDetailsSource;

    @Autowired
    private UserDetailsService userDetailsService; // CustomUserDetailsService

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService); // CustomUserDetailsService 등록
        auth.authenticationProvider(authenticationProvider());
    }

    @Bean
    public AuthenticationProvider authenticationProvider() { // 인증처리 Bean
        return new CustomAuthenticationProvider();
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder(); // 평문을 암호화로 처리해준다. 기본 bcrypt, 아니면 암호화 방식을 param 으로 넣어준다.
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        /**
         * 정적파일은 보안을 거치지 않고 통과한다.
         * 기본적으로는 정적파일 또한 보안을 거친다.
         */
        web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                .antMatchers("/favicon.ico", "/resources/**", "/error");
    }

    /**
     * 메모리 방식 인증
     */
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//
//        String password = passwordEncoder().encode("1111");
//
//        auth.inMemoryAuthentication().withUser("user").password(password).roles("USER");
//        auth.inMemoryAuthentication().withUser("manager").password(password).roles("MANAGER");
//        auth.inMemoryAuthentication().withUser("admin").password(password).roles("ADMIN", "USER", "MANAGER");
//    }

    /**
     * form 인증 api
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "/users", "/users/login/**").permitAll() // web.ignoring() 를 사용하지 않고 여기서 바로 정적파일을 설정해도 되긴하다.(보안필터를 거쳐서 허용, ignoring 은 보안필터 거치지 않음)
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()

                .and()

                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource) // custom authenticationDetailsSource (인증처리 과정에서 처리하는 파라메터 저장하는 클래스), username, password 외에도 추가적으로 파라메터를 설정할 수 있다.
                .defaultSuccessUrl("/")
                .permitAll();


    }
}
