package se.iths.sofia.springauthenticator2fa.controller;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.sofia.springauthenticator2fa.entity.AppUser;
import se.iths.sofia.springauthenticator2fa.repository.AppUserRepository;
import se.iths.sofia.springauthenticator2fa.service.AppUserService;
import se.iths.sofia.springauthenticator2fa.service.QrCodeService;
import se.iths.sofia.springauthenticator2fa.service.TotpService;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final AppUserService appUserService;
    private final AppUserRepository appUserRepository;
    private final TotpService totpService;
    private final QrCodeService qrCodeService;


    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("appUser", new AppUser());
        return "register";
    }


    @PostMapping("/register")
    public String registerUser(@ModelAttribute AppUser appUser, Model model) {
        AppUser savedUser = appUserService.registerUser(appUser);


        if (savedUser.isTwoFactorEnabled()) {
            String qrCode = qrCodeService.generateQrCodeBase64(savedUser);
            model.addAttribute("qrCode", qrCode);
            model.addAttribute("username", savedUser.getUsername());
            return "qr-code";
        }

        return "redirect:/login";
    }


    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }


    @GetMapping("/verify-2fa")
    public String showVerify2faPage() {
        return "verify-2fa";
    }


    @PostMapping("/verify-2fa")
    public String verify2faCode(@RequestParam String code,
                                HttpSession session,
                                Model model) {

        String username = (String) session.getAttribute("username_2fa");

        if (username == null) {
            return "redirect:/login";
        }

        AppUser appUser = appUserRepository.findByUsername(username).orElseThrow();


        if (totpService.isCodeValid(appUser.getSecret(), code)) {
            session.removeAttribute("username_2fa");
            return "redirect:/home";
        }

        model.addAttribute("error", "Invalid code");
        return "verify-2fa";
    }

}
