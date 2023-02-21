package org.iesch.ad.jwtdemo.servicio;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class UsuarioDetailservice implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Map<String, String> usuario = Map.of
                ("Gustavo", "USER",
                 "admin", "ADMIN"
                );
        var rol = usuario.get(username);
        if (rol == null) {
            User.UserBuilder userBuilder = User.withUsername(username);
            String pass = "{noop}" + "1234";
            userBuilder.password(pass).roles("USER");
            return userBuilder.build();
        }
        else throw new UsernameNotFoundException(username);
    }
}
