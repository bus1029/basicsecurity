package io.security.basicsecurity

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.savedrequest.HttpSessionRequestCache

@Configuration(proxyBeanMethods = false)
@ConditionalOnDefaultWebSecurity
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSecurity
class SecurityConfig (
  private val userDetailsService: UserDetailsService
) {

  @Bean
  @Order(2)
  fun filterChain(http: HttpSecurity): SecurityFilterChain {
    setAuthorization(http)
    setLogin(http)
    setLogout(http)
    setRememberMe(http)
    setSessionManagement(http)
    setExceptionHandling(http)

    return http.build()
  }

  private fun setAuthorization(http: HttpSecurity) {
    http.authorizeRequests()
      .antMatchers("/login").permitAll()
      .antMatchers("/user").hasRole("USER")
      .antMatchers("/admin/pay").hasRole("ADMIN")
      .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
      .anyRequest().authenticated()
  }

  private fun setLogin(http: HttpSecurity) {
    http.formLogin()
//      .loginPage("/loginPage")
      .defaultSuccessUrl("/")
      .failureUrl("/login")
      .usernameParameter("userId")
      .passwordParameter("passwd")
      .loginProcessingUrl("/login_proc")
      .successHandler { request, response, authentication ->
        println("authentication ${authentication.name}")
        val requestCache = HttpSessionRequestCache()
        val savedRequest = requestCache.getRequest(request, response)
        response.sendRedirect(savedRequest.redirectUrl)
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

  private fun setRememberMe(http: HttpSecurity) {
    http.rememberMe()
      .rememberMeParameter("remember")
      .tokenValiditySeconds(3600)
      .userDetailsService(userDetailsService)
  }

  private fun setSessionManagement(http: HttpSecurity) {
    http.sessionManagement()
//      .invalidSessionUrl("/invalid")
      .maximumSessions(1)
      .maxSessionsPreventsLogin(true)
//      .expiredUrl("/expired")
  }

  private fun setExceptionHandling(http: HttpSecurity) {
    http.exceptionHandling()
//      .authenticationEntryPoint { _, response, _ ->
//        response.sendRedirect("/login")
//      }
      .accessDeniedHandler { _, response, _ ->
        response.sendRedirect("/denied")
      }
  }

  @Bean
  @Order(1)
  fun httpBasicFilterChain(http: HttpSecurity): SecurityFilterChain {
    setAuthorizeOnlyTest(http)
    httpBasic(http)
    defaultSessionManagement(http)

    return http.build()
  }

  private fun setAuthorizeOnlyTest(http: HttpSecurity) {
    http.antMatcher("/test")
      .authorizeRequests()
      .anyRequest().authenticated()
  }

  private fun httpBasic(http: HttpSecurity) {
    http.httpBasic()
  }

  private fun defaultSessionManagement(http: HttpSecurity) {
    http.sessionManagement()
      .maximumSessions(1)
  }
}