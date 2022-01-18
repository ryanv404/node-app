const sendEmail = require("./sendEmail");

const sendVerificationEmail = async ({name, email, verificationToken, origin}) => {
  const verifyEmail = `${origin}/user/verify-email?token=${verificationToken}&email=${email}`;

  const message = `
    <h4>Thank you for joining!</h4>
    <p>Please verify your email address by clicking on the following link:</p>
    <p><a href="${verifyEmail}">Verify Email</a></p>`;

  return sendEmail({
    to: email,
    subject: "Email Confirmation",
    html: `
      <h4> Hello, ${name}!</h4>
      <br>
      ${message}`
  });
};

module.exports = sendVerificationEmail;