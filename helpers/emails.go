package helpers

import (
	"context"
	"time"

	mailgun "github.com/mailgun/mailgun-go/v4"
)

func SendInvitationEmail(domain, apiString, sender, subject, recipient, code string) (string, error) {
	// // create an instance of Mailgun Client to send
	mg := mailgun.NewMailgun(domain, apiString)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()
	err := mg.DeleteTemplate(ctx, "verifymail")
	if err != nil {
		return "", err
	}
	err = mg.CreateTemplate(ctx, &mailgun.Template{
		Name: "verifymail",
		Version: mailgun.TemplateVersion{
			Template: `
			<div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2">
  <div style="margin:50px auto;width:70%;padding:20px 0">
    <div style="border-bottom:1px solid #eee">
      <a href="" style="font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600">Your Brand</a>
    </div>
    <p style="font-size:1.1em">Hi,</p>
    <p>Thank you for choosing Organized. Use the following OTP to confirm your email address. The code expires shortly so use it ASAP</p>
    <h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">{{.code}}</h2>
    <p style="font-size:0.9em;">Regards,<br />Your Brand</p>
    <hr style="border:none;border-top:1px solid #eee" />
    <div style="float:right;padding:8px 0;color:#aaa;font-size:0.8em;line-height:1;font-weight:300">
      <p>Your Brand Inc</p>
      <p>1600 Amphitheatre Parkway</p>
      <p>California</p>
    </div>
  </div>
</div>
			`,
			Engine: mailgun.TemplateEngineGo,
			Tag:    "v1",
		},
	})
	if err != nil {
		return "", err
	}

	// // gite time for template to show up in the system
	time.Sleep(time.Second * 3)

	message := mg.NewMessage(sender, subject, "")
	message.SetTemplate("verifymail")
	message.AddRecipient(recipient)

	message.AddVariable("code", code)
	// // send message with a 30 second timeout
	_, id, err := mg.Send(ctx, message)
	if err != nil {
		return "", err
	}
	return id, err
}
