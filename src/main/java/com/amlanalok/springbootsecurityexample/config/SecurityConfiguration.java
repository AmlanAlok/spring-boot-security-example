package com.amlanalok.springbootsecurityexample.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

}






/**

 Default implementation of spring security below:

protected void configure(HttpSecurity http) throws Exception {
    this.logger.debug("Using default configure(HttpSecurity). "
            + "If subclassed this will potentially override subclass configure(HttpSecurity).");
    http.authorizeRequests((requests) -> requests.anyRequest().authenticated());
    http.formLogin();
    http.httpBasic();
}
*/