
package com.animeweb.service.mail;



import com.animeweb.entities.EmailDetails;


public interface EmailService {


	String sendSimpleMail(EmailDetails details);


	String sendMailWithAttachment(EmailDetails details);
	String sendLossPassMail (EmailDetails details);
}
