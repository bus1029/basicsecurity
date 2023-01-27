package io.security.basicsecurity

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Configuration(proxyBeanMethods = false)
@ConditionalOnDefaultWebSecurity
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
class SecurityConfig {
  @Bean
  @Order(SecurityProperties.BASIC_AUTH_ORDER)
  fun filterChain(http: HttpSecurity): SecurityFilterChain {
    return http
      .authorizeRequests()
      .anyRequest().authenticated()
      .and()
      .formLogin()
//      .loginPage("/loginPage")
      .defaultSuccessUrl("/")
      .failureUrl("/login")
      .usernameParameter("userId")
      .passwordParameter("passwd")
      .loginProcessingUrl("/login_proc")
      .successHandler { _, response, authentication ->
        println("authentication ${authentication.name}")
        response.sendRedirect("/")
      }
      .failureHandler { _, response, exception ->
        println("exception ${exception.message}")
        response.sendRedirect("/login")
      }
      .permitAll()
      .and()
      .build()
  }
}