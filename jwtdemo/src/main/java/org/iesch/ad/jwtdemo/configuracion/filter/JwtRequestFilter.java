package org.iesch.ad.jwtdemo.configuracion.filter;

import org.iesch.ad.jwtdemo.servicio.JwtService;
import org.iesch.ad.jwtdemo.servicio.UsuarioDetailservice;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component

public class JwtRequestFilter extends OncePerRequestFilter {
    @Autowired
    JwtService jwtService;

    @Autowired
    UsuarioDetailservice usuario;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authorizationHeader = request.getHeader("Authorization");
        String username = null;
        String jwt = null;

        if (authorizationHeader!= null && authorizationHeader.startsWith("Bearer ")) {
            jwt = authorizationHeader.substring(7);
            username = jwtService.extractUsername(jwt);
        }
        if (authorizationHeader!= null && SecurityContextHolder.getContext().getAuthentication() == null) {

           UserDetails userDetails = this.usuario.loadUserByUsername(username);
           if(jwtService.validateToken(jwt, userDetails)) {
               UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken
                       (userDetails, null, userDetails.getAuthorities());
               AuthenticationToken.setDetails(new AuthenticationToken().buildDetails(request));
               SecurityContextHolder.getContext().setAuthentication(authentication);
           }
        }
        filterChain.doFilter(request, response);

    }

}
