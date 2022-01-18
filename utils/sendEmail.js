const nodemailer = require("nodemailer");

const sendEmail = async ({to, subject, html}) => {
  // Create an Ethereal test acct to send test messages that are stored
  // on the ethereal.email website.
  let testAccount = await nodemailer.createTestAccount();

  // Create a SMTP transporter object
  let transporter = nodemailer.createTransport({
    host: testAccount.smtp.host,
    port: testAccount.smtp.port,
    secure: testAccount.smtp.secure,
    auth: {
      user: testAccount.user,
      pass: testAccount.pass,
    },
  });

  // Message object
  return transporter.sendMail({
    from: 'Ryan <ryan@example.com>',
    to,
    subject,
    html,
  });
};

module.exports = sendEmail;
