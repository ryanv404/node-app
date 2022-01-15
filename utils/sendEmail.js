const nodemailer = require("nodemailer");

const sendEmail = async ({to, subject, html}) => {
  let testAccount = await nodemailer.createTestAccount();

  let transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    secure: false,
    auth: {
      user: testAccount.user,
      pass: testAccount.pass
    }
  });

  return transporter.sendMail({
    from: '"Ryan" <ryan@example.com>',
    to,
    subject,
    html
  });
};

module.exports = sendEmail;
