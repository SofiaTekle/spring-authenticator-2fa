package se.iths.sofia.springauthenticator2fa.service;

import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.springframework.stereotype.Service;

/**
 * Hanterar Time-based One-Time Password för tvåfaktorsautentisering:
 * generering av secret, verifiering av koder och skapande av otpauth-URL.
 */
@Service
public class TotpService {

    // Skapar en hemlig nyckel för en användare som aktiverar 2FA.
    public String generateSecret() {
        return new DefaultSecretGenerator().generate();
    }


    public boolean isCodeValid(String secret, String code) {
        CodeVerifier verifier = new DefaultCodeVerifier(
                new DefaultCodeGenerator(),
                new SystemTimeProvider()
        );

        return verifier.isValidCode(secret, code);
    }

    public String getOtpAuthURL(String secret, String username) {
        return "otpauth://totp/SpringAuthenticator2FA:" + username +
                "?secret=" + secret +
                "&issuer=SpringAuthenticator2FA";
    }


}
