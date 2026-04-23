package se.iths.sofia.springauthenticator2fa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import se.iths.sofia.springauthenticator2fa.entity.AppUser;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUsername(String username);
}
