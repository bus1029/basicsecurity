package io.security.basicsecurity

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity
import org.springframework.boot.autoconfigure.security.SecurityProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration(proxyBeanMethods = false)
@ConditionalOnDefaultWebSecurity
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
class SecurityConfig {
  @Bean
  @Order(SecurityProperties.BASIC_AUTH_ORDER)
  fun filterChain(http: HttpSecurity): SecurityFilterChain {
    http.authorizeRequests()
      .anyRequest().authenticated()
    setLogin(http)
    setLogout(http)

    return http.build()
  }

  private fun setLogin(http: HttpSecurity) {
    http.formLogin()
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
  }

  private fun setLogout(http: HttpSecurity) {
    http.logout()
      .logoutUrl("/logout")
      .logoutSuccessUrl("/login")
      .addLogoutHandler { request, _, _ ->
        val session = request.session
        session.invalidate()
      }
      .logoutSuccessHandler { _, response, _ ->
        response.sendRedirect("/login")
      }
      .deleteCookies("remember-me")
  }
}