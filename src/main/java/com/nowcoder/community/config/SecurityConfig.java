package com.nowcoder.community.config;

import com.nowcoder.community.entity.User;
import com.nowcoder.community.service.UserService;
import com.nowcoder.community.util.CommunityUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    @Override
    public void configure(WebSecurity web) throws Exception {
        //忽略静态资源的访问
        web.ignoring().antMatchers("/resources/**");
    }

    //AuthenticationManager:认证的核心接口
    //AuthenticationManagerBuilder:用户构建AuthenticationManager的工具
    //ProviderManager：AuthenticationManager接口的默认实现类
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //对认证进行处理
        //内置的认证规则
        // auth.userDetailsService(userService).passwordEncoder(new Pbkdf2PasswordEncoder("12345"));
        //自定义认证规则
        //AuthenticationProvider:ProviderManager持有一组AuthenticationProvider，每一个AuthenticationProvider负责一种认证
        auth.authenticationProvider(new AuthenticationProvider() {
            //Authentication:用于封装认证信息的接口，不同的实现类代表不同的类型的认证信息
            @Override
            public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                String username = authentication.getName();
                String password = (String) authentication.getCredentials();
                User user = userService.findUserByName(username);
                if (user == null){
                    throw new UsernameNotFoundException("帐号不存在！");
                }
                password = CommunityUtil.md5(password) + user.getSalt();
                if (!user.getPassword().equals(password)){
                    throw new BadCredentialsException("密码错误！");
                }
                return new UsernamePasswordAuthenticationToken(user,user.getPassword(),user.getAuthorities());
            }
            //当前接口支持的认证类型
            @Override
            public boolean supports(Class<?> aClass) {
                //UsernamePasswordAuthenticationToken:Authentication接口的常用实现类，用于账号密码的认证
                return UsernamePasswordAuthenticationToken.class.equals(aClass);
            }
        });
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //登录相关配置
        http.formLogin().loginPage("/loginpage") //处理登录界面
                        .loginProcessingUrl("/login") //登录的处理路径，需要配在表单上
                //成功时如何处理
                        .successHandler(new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                response.sendRedirect(request.getContextPath()+"/index");
                            }
                        })
                //失败式如何处理
                        .failureHandler(new AuthenticationFailureHandler() {
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                                request.setAttribute("error",e.getMessage());
                                request.getRequestDispatcher("/loginpage").forward(request,response);
                            }
                        });
        //退出的设置
        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect(request.getContextPath()+"/index");
                    }
                });
        //权限配置
        http.authorizeRequests()
                .antMatchers("/letter").hasAnyAuthority("USER","ADMIN")
                .antMatchers("/admin").hasAnyAuthority("ADMIN")
                .and().exceptionHandling().accessDeniedPage("/denied");
        //添加一个filter在验证账号密码之前处理验证码
        http.addFilterBefore(new Filter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
                HttpServletRequest request = (HttpServletRequest)servletRequest;
                HttpServletResponse response = (HttpServletResponse)servletResponse;
                //只处理登录请求
                if (request.getServletPath().equals("/login")){
                    String verifyCode = request.getParameter("verifyCode");
                    if (verifyCode == null || !verifyCode.equalsIgnoreCase("1234")){
                        request.setAttribute("error","验证码错误");
                        request.getRequestDispatcher("/loginpage").forward(request,response);
                        return;
                    }
                }
                //让请求继续
                filterChain.doFilter(request,response);
            }
        }, UsernamePasswordAuthenticationFilter.class);
        //记住我
        http.rememberMe().tokenRepository(new InMemoryTokenRepositoryImpl()).tokenValiditySeconds(3600*24).userDetailsService(userService);
    }
}
