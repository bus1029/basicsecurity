package io.security.basicsecurity

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager

@Configuration
class SecurityUserConfig {
    @Bean
    fun userDetailsService(): UserDetailsService {
        return InMemoryUserDetailsManager(
                createUser(),
                createSys(),
                createAdmin()
        )
    }

    private fun createUser(): UserDetails {
        return User.withDefaultPasswordEncoder()
                .username("user")
                .password("1111")
                .roles("USER")
                .build()
    }

    private fun createSys(): UserDetails {
        return User.withDefaultPasswordEncoder()
                .username("sys")
                .password("1111")
                .roles("SYS")
                .build()
    }

    private fun createAdmin(): UserDetails {
        return User.withDefaultPasswordEncoder()
                .username("admin")
                .password("1111")
                .roles("ADMIN")
                .build()
    }
}