package com.gskart.user.security.services;

import com.gskart.user.security.models.GSKartUserDetails;
import com.gskart.user.entities.User;
import com.gskart.user.repositories.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class GSKartUserService implements UserDetailsService {
    private UserRepository userRepository;

    public GSKartUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> optionalUser = userRepository.findByUsername(username);
        if(optionalUser.isEmpty()){
            throw new UsernameNotFoundException(String.format("User with Username %s not found.", username));
        }
        return new GSKartUserDetails(optionalUser.get());
    }
}
