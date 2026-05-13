package se.iths.sofia.springauthenticator2fa.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/*
 Stoppar användaren från att nå skyddade sidor
    om de inte har klarat 2FA ännu
 */

@Component
public class TwoFactorFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // kolla att användaren faktiskt är inloggad
        if (auth != null && auth.isAuthenticated() &&
                !(auth instanceof AnonymousAuthenticationToken)) {
            
            HttpSession session = request.getSession(false);

            if (session != null) {

                Boolean requires2fa = (Boolean) session.getAttribute("requires_2fa");

                // om användaren inte har 2FA aktiverat -> släpp igenom
                if (requires2fa == null || !requires2fa) {
                    filterChain.doFilter(request, response);
                    return;
                }

                //  Kontrollerar om användaren har verifierat 2FA denna session
                Boolean verified = (Boolean) session.getAttribute("two_factor_verified");

                String path = request.getRequestURI();

                // Endpoints som alltid är tillåtna även utan 2FA
                boolean allowedPath =
                        path.equals("/verify-2fa") ||
                                path.equals("/logout") ||
                                path.equals("/login") ||
                                path.equals("/register") ||
                                path.startsWith("/css");

                // Blockerar åtkomst till skyddade endpoints om 2FA inte är genomförd
                if ((verified == null || !verified) && !allowedPath) {
                    response.sendRedirect("/verify-2fa");
                    return;
                }

            }

        }

        filterChain.doFilter(request, response);
    }
}
