

// const Contact = require('../models/contact');
// const nodemailer = require('nodemailer');

// // Controller function to handle contact form submission
// const handleContactForm = async (req, res) => {
//   try {
//     const { name, email, phone, subject, message } = req.body;

//     // Basic Validation 
//     if (!name || !email || !phone || !subject || !message) {
//       return res.status(400).json({ error: 'All fields are required.' });
//     }

//     //  Save the contact message to MongoDB
//     const newContact = new Contact({ name, email, phone, subject, message });
//     await newContact.save();
//     console.log("Contact saved:", newContact);
//     //  Setup Nodemailer transport using Gmail
//     const transporter = nodemailer.createTransport({
//       service: 'gmail',
//       auth: {
//         user: process.env.EMAIL_USER,     // Your Gmail
//         pass: process.env.EMAIL_PASS      // App Password 
//       }
//     });

//     //  Email content to admin
//     const mailOptions = {
//       from: `"PastPortals Contact" <${process.env.EMAIL_USER}>`,
//       to: process.env.ADMIN_EMAIL,
//       subject: `New Contact Form Submission: ${subject}`,
//       html: `
//         <h3>You received a new contact message:</h3>
//         <p><strong>Name:</strong> ${name}</p>
//         <p><strong>Email:</strong> ${email}</p>
//         <p><strong>Phone:</strong> ${phone}</p>
//         <p><strong>Subject:</strong> ${subject}</p>
//         <p><strong>Message:</strong><br/> ${message}</p>
//       `
//     };

//     //  Send the email
//     await transporter.sendMail(mailOptions);

//     // Success response
//     res.status(200).json({ success: true, message: "Message sent successfully." });

//   } catch (error) {
//     console.error(" Error in handleContactForm:", error);
//     res.status(500).json({ error: "Server Error. Please try again later." });
//   }
// };

// module.exports = { handleContactForm };
const Contact = require('../models/contact');
const nodemailer = require('nodemailer');

const handleContactForm = async (req, res) => {
  try {
    const { name, email, phone, subject, message } = req.body;

    // Basic Validation
    if (!name || !email || !phone || !subject || !message) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    // Save the contact message to MongoDB
    const newContact = new Contact({ name, email, phone, subject, message });
    await newContact.save();
    console.log("Contact saved:", newContact);

    // Setup Nodemailer transport using Gmail
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
      }
    });

  const mailOptionsAdmin = {
  from: `"PastPortals Contact" <${process.env.EMAIL_USER}>`,
  to: process.env.ADMIN_EMAIL,
  subject: `📬 New Contact Form Submission: ${subject}`,
  html: `
    <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #f4f7fa; padding: 32px;">
      <div style="max-width: 500px; margin: auto; background: #fff; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.08); padding: 24px;">
        <h2 style="color: #007bff; margin-bottom: 12px;">🚀 New Contact Message Received</h2>
        <p style="font-size: 1.1rem; color: #333;">You have received a new message via PastPortals contact form:</p>
        <hr style="margin: 18px 0;">
        <table style="width: 100%; font-size: 1rem;">
          <tr>
            <td style="padding: 6px 0; color: #555;"><strong>Name:</strong></td>
            <td style="padding: 6px 0;">${name}</td>
          </tr>
          <tr>
            <td style="padding: 6px 0; color: #555;"><strong>Email:</strong></td>
            <td style="padding: 6px 0;"><a href="mailto:${email}" style="color: #007bff;">${email}</a></td>
          </tr>
          <tr>
            <td style="padding: 6px 0; color: #555;"><strong>Phone:</strong></td>
            <td style="padding: 6px 0;">${phone}</td>
          </tr>
          <tr>
            <td style="padding: 6px 0; color: #555;"><strong>Subject:</strong></td>
            <td style="padding: 6px 0;">${subject}</td>
          </tr>
        </table>
        <div style="margin-top: 18px; padding: 16px; background: #f0f4ff; border-radius: 8px;">
          <strong style="color: #34495e;">Message:</strong>
          <p style="margin-top: 8px; color: #222;">${message}</p>
        </div>
        <hr style="margin: 24px 0;">
        <p style="font-size: 0.95rem; color: #888;">Received on: <strong>${new Date().toLocaleString()}</strong></p>
        <p style="font-size: 0.95rem; color: #888;">PastPortals Admin Panel</p>
      </div>
    </div>
  `
};

    // Send email to admin
    await transporter.sendMail(mailOptionsAdmin);

    // Email content to user (confirmation)
 const mailOptionsUser = {
  from: `"PastPortals Team" <${process.env.EMAIL_USER}>`,
  to: email,
  subject: "🌟 Thank You for Contacting PastPortals!",
  html: `
    <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #f4f7fa; padding: 32px;">
      <div style="max-width: 500px; margin: auto; background: #fff; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.08); padding: 24px;">
        <h2 style="color: #007bff; margin-bottom: 12px;">Hello ${name},</h2>
        <p style="font-size: 1.1rem; color: #333;">
          Thank you for reaching out to <strong>PastPortals</strong>!<br>
          We’ve received your message and our team will get back to you soon.
        </p>
        <hr style="margin: 18px 0;">
        <h4 style="color: #34495e;">Your Submission:</h4>
        <table style="width: 100%; font-size: 1rem;">
          <tr>
            <td style="padding: 6px 0; color: #555;"><strong>Subject:</strong></td>
            <td style="padding: 6px 0;">${subject}</td>
          </tr>
        </table>
        <div style="margin-top: 12px; padding: 16px; background: #f0f4ff; border-radius: 8px;">
          <strong style="color: #34495e;">Message:</strong>
          <p style="margin-top: 8px; color: #222;">${message}</p>
        </div>
        <hr style="margin: 24px 0;">
        <p style="font-size: 1rem; color: #555;">
          If your query is urgent, feel free to reply to this email.<br>
          <span style="color: #007bff;">We appreciate your interest in PastPortals!</span>
        </p>
        <p style="font-size: 1rem; color: #888; margin-top: 24px;">
          Best regards,<br>
          <strong>PastPortals Team</strong>
        </p>
        <p style="font-size: 0.9rem; color: #bbb; margin-top: 12px;">
          This is an automated confirmation. You’ll hear from us soon!
        </p>
      </div>
    </div>
  `
};

    // Send confirmation email to user
    await transporter.sendMail(mailOptionsUser);

    // Success response
    res.status(200).json({ success: true, message: "Message sent successfully." });

  } catch (error) {
    console.error("Error in handleContactForm:", error);
    res.status(500).json({ error: "Server Error. Please try again later." });
  }
};

module.exports = { handleContactForm };
