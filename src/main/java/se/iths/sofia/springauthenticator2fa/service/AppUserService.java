package se.iths.sofia.springauthenticator2fa.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import se.iths.sofia.springauthenticator2fa.entity.AppUser;
import se.iths.sofia.springauthenticator2fa.repository.AppUserRepository;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AppUserService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final TotpService totpService;


    public AppUser registerUser(AppUser appUser) {
        appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
        appUser.setRole("USER");

        if (appUser.isTwoFactorEnabled()) {
            appUser.setSecret(totpService.generateSecret());
        }

        return appUserRepository.save(appUser);
    }

    public Optional<AppUser> findByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }

}
