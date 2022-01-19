const sendEmail = require("./sendEmail");

const sendResetPasswordEmail = async ({name, email, token, origin}) => {
  const resetURL = `${origin}/user/reset-password?token=${token}&email=${email}`;
  
  const message = `
    <p>Please reset your password by clicking on the following link:<p>
    <p><a href="${resetURL}">Reset Password</a></p>`;

  return sendEmail({
    to: email,
    subject: 'Reset Password',
    html: `
      <h4>Hello, ${name}!</h4>
      <br>
      ${message}`
  });
};

module.exports = sendResetPasswordEmail;
