package se.iths.sofia.springauthenticator2fa.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import se.iths.sofia.springauthenticator2fa.entity.AppUser;

import java.io.ByteArrayOutputStream;
import java.util.Base64;

/**
 * Skapar en QR-kod som användaren kan scanna med en authenticator-app.
 */
@Service
@RequiredArgsConstructor
public class QrCodeService {
    private final TotpService totpService;

    /**
     * Genererar QR-koden som Base64 så att den kan visas direkt i HTML.
     */
    public String generateQrCodeBase64(AppUser user) {
        try {
            String otpAuthUrl = totpService.getOtpAuthURL(user.getSecret(), user.getUsername());


            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(otpAuthUrl, BarcodeFormat.QR_CODE, 250, 250);


            ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);


            byte[] pngData = pngOutputStream.toByteArray();


            return Base64.getEncoder().encodeToString(pngData);
        } catch (Exception e) {
            throw new RuntimeException("Could not generate QR code", e);
        }
    }

}
