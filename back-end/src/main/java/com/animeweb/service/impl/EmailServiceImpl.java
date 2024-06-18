
package com.animeweb.service.impl;

import java.io.File;
import java.util.Date;

import com.animeweb.entities.EmailDetails;
import com.animeweb.service.mail.EmailService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService {
    private final String SECRET_KEY = "your_secret_key";
    @Autowired
    private JavaMailSender javaMailSender;

    @Value("${spring.mail.username}")
    private String sender;

    public String sendSimpleMail(EmailDetails details) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);
            mimeMessageHelper.setFrom(sender);
            mimeMessageHelper.setTo(details.getRecipient());
            mimeMessageHelper.setText(details.getMsgBody(),true);
            mimeMessageHelper.setSubject(details.getSubject());
            javaMailSender.send(mimeMessage);
            return "Mail Sent Successfully...";
        } catch (Exception e) {
            return "Error while Sending Mail";
        }
    }

        public String sendLossPassMail(EmailDetails details) {
            try {
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);

                mimeMessageHelper.setFrom(sender);
                mimeMessageHelper.setTo(details.getRecipient());
                mimeMessageHelper.setSubject(details.getSubject());

                String emailContent = "<!DOCTYPE html>" +
                        "<html>" +
                        "<head>" +
                        "<style>" +
                        "    .container { border: 1px solid #e0e0e0; padding: 20px; font-family: Arial, sans-serif; }" +
                        "    .header { color: red; font-size: 20px; font-weight: bold; text-align: right; }" +
                        "    .content { margin-top: 20px; }" +
                        "    .btn { display: block; width: 200px; padding: 10px; background-color: red; color: white!important; text-align: center; text-decoration: none; border-radius: 5px; margin: 20px 0; }" +
                        "    .footer { font-size: 12px; color: #888888; margin-top: 20px; }" +
                        "</style>" +
                        "</head>" +
                        "<body>" +
                        "<div class='container'>" +
                        "    <div class='header'>AnimeWeb.site</div>" +
                        "    <div class='content'>" +
                        "        <p>Chào " + details.getRecipient() + ",</p>" +
                        "        <p>AnimeWeb đã nhận được yêu cầu thay đổi mật khẩu của bạn.</p>" +
                        "        <p>Nếu bạn chính là người đã gửi yêu cầu, xin hãy bấm vào nút sau và thực hiện đổi mật khẩu:</p>" +
                        "        <a href='" + details.getMsgBody() + "' class='btn'>Đổi mật khẩu</a>" +
                        "        <p>hoặc <a href='" + details.getMsgBody() + "'>" + details.getMsgBody() + "</a></p>" +
                        "        <p><strong>Lưu ý:</strong> Đường dẫn trên chỉ có giá trị trong vòng 1 giờ kể từ thời điểm này.</p>" +
                        "        <p>Nếu hành động này không phải do bạn yêu cầu, xin vui lòng bỏ qua email này, mật khẩu của bạn sẽ không thay đổi.</p>" +
                        "        <p>Thân mến,</p>" +
                        "        <p>AnimeWeb</p>" +
                        "    </div>" +
                        "    <div class='footer'>" +
                        "        <p>Copyright © animeweb.site</p>" +
                        "        <p>IMAD Co., Ltd.</p>" +
                        "        <p>Email: 20130305@st.hcmuaf.edu.vn</p>" +
                        "    </div>" +
                        "</div>" +
                        "</body>" +
                        "</html>";

                mimeMessageHelper.setText(emailContent, true);

                javaMailSender.send(mimeMessage);
                return "Mail Sent Successfully...";
            } catch (Exception e) {
                return "Error while Sending Mail: " + e.getMessage();
            }
        }

    public String sendMailWithAttachment(EmailDetails details) {
        try {
            MimeMessage mimeMessage = javaMailSender.createMimeMessage();
            MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);
            mimeMessageHelper.setFrom(sender);
            mimeMessageHelper.setTo(details.getRecipient());
            mimeMessageHelper.setText(details.getMsgBody());
            mimeMessageHelper.setSubject(details.getSubject());
            FileSystemResource file = new FileSystemResource(new File(details.getAttachment()));
            mimeMessageHelper.addAttachment(file.getFilename(), file);
            javaMailSender.send(mimeMessage);
            return "Mail sent Successfully";
        } catch (MessagingException e) {
            return "Error while sending mail!!!";
        } catch (Exception e) {
            return "Error while sending mail!!!";
        }
    }
    public String generateTokenEmail(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 giờ
                .signWith(SignatureAlgorithm.HS512, SECRET_KEY)
                .compact();
    }
    public String validateTokenEmail(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (ExpiredJwtException | SignatureException e) {
            return null;
        }
    }
}

