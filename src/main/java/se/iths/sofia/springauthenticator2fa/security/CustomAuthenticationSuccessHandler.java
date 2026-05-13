package se.iths.sofia.springauthenticator2fa.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import se.iths.sofia.springauthenticator2fa.entity.AppUser;
import se.iths.sofia.springauthenticator2fa.repository.AppUserRepository;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {


    private final AppUserRepository appUserRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();

        AppUser user = appUserRepository.findByUsername(username)
                .orElseThrow();

        HttpSession session = request.getSession();

        if (user.isTwoFactorEnabled()) {
            session.setAttribute("username_2fa", username);
            session.setAttribute("two_factor_verified", false);
            session.setAttribute("requires_2fa", true);
            response.sendRedirect("/verify-2fa");
        } else {
            // Användare utan 2FA markeras som verifierade direkt
            session.setAttribute("two_factor_verified", true);
            session.setAttribute("requires_2fa", false);
            response.sendRedirect("/home");
        }


    }
}
