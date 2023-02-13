package io.security.basicsecurity

import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpSession

@RestController
class SecurityController {
  @GetMapping("/")
  fun index(httpSession: HttpSession): String {
    val authentication = SecurityContextHolder.getContext().authentication
    val securityContext =
      httpSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY) as SecurityContext
    if (authentication.equals(securityContext.authentication)) {
      return "home true"
    }

    return "home"
  }

  @GetMapping("/thread")
  fun thread(): String {
    val authentication = SecurityContextHolder.getContext().authentication
    Thread {
      val newAuthentication = SecurityContextHolder.getContext().authentication
      if (!authentication.equals(newAuthentication)) {
        println("Not equals")
      }
    }.start()
    return "thread"
  }

  @GetMapping("loginPage")
  fun loginPage(): String {
    return "loginPage"
  }

  @GetMapping("/user")
  fun user(): String {
    return "user"
  }

  @GetMapping("/admin/pay")
  fun adminPay(): String {
    return "adminPay"
  }

  @GetMapping("/admin/**")
  fun admin(): String {
    return "admin"
  }

  @GetMapping("/login")
  fun login(): String {
    return "login"
  }

  @GetMapping("/denied")
  fun denied(): String {
    return "Access is denied"
  }
}