import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';

@Injectable()
export class EmailService {
    // sendMail(email: string, arg1: string, arg2: string) {
    //     throw new Error('Method not implemented.');
    // }
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com', // Replace with your SMTP server
      port: 465,
      secure: true, // true for 465, false for other ports
      auth: {
        user: 'ysly305@gmail.com', // Replace with your email
        pass: 'kewq kfna lkux ygiv', // Replace with your email password
      },
    });
  }

// async sendMail(to: string, otp: string) {
//     try {
//       const info = await this.transporter.sendMail({
//         from: 'NestJS App <ysly305@gmail.com>', // Your name and Gmail email address
//         to,
//         subject: 'OTP Verification',
//         text: `Hello, ${to.split('@')[0]}!\nYour OTP for verification is: ${otp}`,
//       });
//       console.log('Email sent: %s', info.messageId);
//       return true; // Return true if email is sent successfully
//     } catch (error) {
//       console.error('Error sending email:', error);
//       return false; // Return false if there's an error sending email
//     }
//   }

async sendMail(to: string, subject: string, text: string) {
  try {
    const info = await this.transporter.sendMail({
      from: 'LALAJI KI HOSTEL - NestJS App <ysly305@gmail.com>', // Replace with your name and Gmail email address
      to,
      subject: 'OTP Verification',
      // subject: 'Notification',
      text,
    });
    console.log('Email sent: %s', info.messageId);
    return true; // Return true if email is sent successfully
  } catch (error) {
    console.error('Error sending email:', error);
    return false; // Return false if there's an error sending email
  }
}
  
}
