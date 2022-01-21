const nodemailer = require("nodemailer");

const sendEmail = async ({to, subject, html}) => {
  // Create an Ethereal test acct to send test messages that are stored
  // on the ethereal.email website.
  // let testAccount = await nodemailer.createTestAccount();

  // Create a SMTP transporter object
  let transporter = nodemailer.createTransport({
    host: "smtp.ethereal.email",
    port: 587,
    auth: {
      user: "vicenta.douglas77@ethereal.email",
      pass: "npawFPdcBhpHWNm6GT",
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
