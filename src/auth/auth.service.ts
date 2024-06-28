// src/auth/auth.service.ts

import { Injectable, UnauthorizedException, BadRequestException, NotFoundException, ExecutionContext, CanActivate } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma.service';
import * as bcrypt from 'bcrypt';
import { EmailService } from '../email/email.service';
import { generateOTP } from '../utils/otp';
import { v4 as uuidv4 } from 'uuid'; // Import uuid for generating unique tokens
import { RegisterDto } from './dto/register.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { JwtAuthGuard } from './jwt-auth.guard';

// export interface User {
//   email: string;
//   password: string;
//   name: string;
//   isVerified: boolean;
// }

@Injectable()
export class AuthService {
  // private users: User[] = []; // Initialize as an empty array
  users: any;
  findOne: any;
  resetPassword(email: any, oldPassword: string, newPassword: string) {
    throw new Error('Method not implemented.');
  }

// @Injectable()
// export class PublicGuard implements CanActivate {
//   canActivate(context: ExecutionContext): boolean {
//     // Always return true to bypass authorization for specific routes
//     return true;
  // }
// }

// @Injectable()
// export class PrivateGuard extends JwtAuthGuard implements CanActivate {
//   canActivate(context: ExecutionContext): boolean {
//     return super.canActivate(context); // Use existing JWT auth logic
//   }
// }

  // const emailSent = await this.emailService.sendMail(email, 'Login Successful', 'You have successfully logged in to your account.');
  // changePassword(email: string, password: string, newPassword: string) {
  //   throw new Error('Method not implemented.');
  // }
  // validateStudent(email: string, password: string) {
  //     throw new Error('Method not implemented.');
  // }

  private blacklistedTokens: Set<string> = new Set(); // In-memory token blacklist

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly emailService: EmailService,
  ) {}

  async register(email: string, password: string, name: string) {
    try {
      // Validate email format
      if (!this.isValidEmail(email)) {
        throw new BadRequestException('Invalid email format');
      }

        // Check if email already exists
        const existingStudent = await this.prisma.student.findUnique({ where: { email } });
        if (existingStudent) {
          throw new Error('Email is already registered');
        }

    const hashedPassword = await bcrypt.hash(password, 10);
    const otp = generateOTP();

    const student = await this.prisma.student.create({
      data: {
        email,
        password: hashedPassword,
        name,
        otp,
        isVerified: false, // Ensure this field is added in your schema
      },
    });

    // await this.emailService.sendMail(email, `Your OTP code is : ${otp}`, 'OTP Code');

    // const emailSent = await this.emailService.sendMail(email, 'Your OTP Code', `Your OTP code is : ${otp}`);
    //   if (!emailSent) {
    //     throw new Error('Failed to send OTP email');
    //   }

    // const emailBody = `Hello, Dear ${name}!\nYour OTP for verification is: ${otp}`;
    const emailBody = `Hello ${name},\n\nWelcome to Lala Ji Ki Hevali!\n\nYour OTP for email verification is: ${otp}\n\nPlease verify your email to complete your registration.\n\nThank you!`;
      const emailSent = await this.emailService.sendMail(email, 'Account Verification with OTP', emailBody);
      if (!emailSent) {
        throw new Error('Failed to send OTP email');
      }

    return student;
  }catch (error) {

// Handle unique constraint violation error
      console.error('Error registering student:', error.message);
      throw new Error('Failed to register student');
    }
  }
  // isValidEmail(email: string) {
  //   throw new Error('Method not implemented.');
  // }

  async verifyEmail(email: string, otp: string) {
    const student = await this.prisma.student.findUnique({ where: { email } });
    if (!student || student.otp !== otp) {
      throw new UnauthorizedException('Invalid OTP');
    }

    await this.prisma.student.update({
      where: { email },
      data: { isVerified: true, otp: null },
    });

  //   await this.emailService.sendMail(email, 'Congratulations! Your account has been verified. Now you can login.', 'Account Verified');

  //   return { message: 'Email verified successfully' };
  // }

  // const emailSent = await this.emailService.sendMail(email, 'Congratulations!', 'Your account has been verified. Now you can login.');
  //   if (!emailSent) {
  //     throw new Error('Failed to send verification email');
  //   }

  const emailBody = `Hello ${student.name},\n\nCongratulations! Your email has been successfully verified.\n\nYou can now log in to your account and enjoy our services.\n\nThank you for verifying your email!\n\nBest regards,\nLala Ji Ki Hevali Mai Aap Ka Swagat Hai!`;
    const emailSent = await this.emailService.sendMail(email, 'Email Verification Success', emailBody);
    if (!emailSent) {
      throw new Error('Failed to send verification email');
    }

    return { message: 'Email verified successfully' };
  }

  async validateStudent(email: string, password: string): Promise<any> {
    const student = await this.prisma.student.findUnique({ where: { email } });
    if (student && await bcrypt.compare(password, student.password)) {
      return student;
    }
    return null;
  }

  // async login(student: any) {
  //   const payload = { email: student.email, sub: student.id };
  //   return {
  //     access_token: this.jwtService.sign(payload),
  //   };
  // }


  async login(email: string, password: string) {
    const student = await this.prisma.student.findUnique({ where: { email } });
    if (!student) {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (!student.isVerified) {
      throw new UnauthorizedException('Your account is not verified. Please verify your email first.');
    }

    const isPasswordValid = await bcrypt.compare(password, student.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { email: student.email, sub: student.id };
    const token = this.jwtService.sign(payload);

  //   // Send login success email
  //   await this.emailService.sendMail(email, 'You have Successfully Logged in to your Account.', 'Login Success');

  //   return {
  //     access_token: token,
  //   };
  // }

  const emailBody = `Hello ${student.name},\n\nCongrats! You have successfully logged in to your account.\n\nIf this wasn't you, please secure your account immediately.\n\nBest regards,\nLala Ji Ki Hevali Mai Aap Ka Swagat Hai!`;
  // const emailSent = await this.emailService.sendMail(email, 'Login Successful', 'You have successfully logged in to your account.');
  const emailSent = await this.emailService.sendMail(email, 'Login Successful', emailBody);
    if (!emailSent) {
      throw new Error('Failed to send login confirmation email');
    }

    return {
      access_token: token,
    };
  }

  private isValidEmail(email: string): boolean {
    const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(([^<>()[\]\.,;:\s@"]+\.)+[^<>()[\]\.,;:\s@"]{2,})$/i;
    return re.test(String(email).toLowerCase());
  }

  async logout(token: string) {
    this.blacklistToken(token);
    return { message: 'Logout successful' };
  }

  private blacklistToken(token: string) {
    this.blacklistedTokens.add(token);
  }

  isTokenBlacklisted(token: string): boolean {
    return this.blacklistedTokens.has(token);
  }



  async sendPasswordResetEmail(email: string) {
    const student = await this.prisma.student.findUnique({ where: { email } });
    if (!student) {
      throw new BadRequestException('Invalid email');
    }

    const resetToken = uuidv4();
    const resetTokenExpiry = new Date();
    // resetTokenExpiry.setHours(resetTokenExpiry.getHours() + 1); // Token valid for 1 hour

    resetTokenExpiry.setMinutes(resetTokenExpiry.getMinutes() + 5); // Token valid for 5 minutes


    await this.prisma.student.update({
      where: { email },
      data: { resetToken, resetTokenExpiry },
    });

    const resetLink = `http://your-frontend-url/reset-password?token=${resetToken}`;

    const emailBody = `Hello ${student.name},\n\nYou requested to reset your password. Please click the link below to reset your password:\n\n${resetLink}\n\nIf you did not request this, please ignore this email.\n\nThank you!`;
    const emailSent = await this.emailService.sendMail(email, 'Password Reset Request', emailBody);
    if (!emailSent) {
      throw new Error('Failed to send password reset email');
    }

    return { message: 'Password reset email sent' };
  }

  // // Here only new password reset don't validate old password.
  // async resetPassword(token: string, newPassword: string) {
  //   const student = await this.prisma.student.findFirst({ where: { resetToken: token, resetTokenExpiry: { gt: new Date() } } });
  //   if (!student) {
  //     throw new UnauthorizedException('Invalid or expired reset token');
  //   }

  //   const hashedPassword = await bcrypt.hash(newPassword, 10);

  //   await this.prisma.student.update({
  //     where: { email: student.email },
  //     data: { password: hashedPassword, resetToken: null, resetTokenExpiry: null },
  //   });

  //   return { message: 'Password reset successful' };
  // }



  // Here we are validating the old password before changing it.
  // async resetPassword(email: string, oldPassword: string, newPassword: string) {
  //   const student = await this.prisma.student.findUnique({ where: { email } });
  //   if (!student) {
  //     throw new BadRequestException('Invalid email');
  //   }

  //   const isOldPasswordValid = await bcrypt.compare(oldPassword, student.password);
  //   if (!isOldPasswordValid) {
  //     throw new UnauthorizedException('Old password is incorrect');
  //   }

  //   const hashedNewPassword = await bcrypt.hash(newPassword, 10);
  //   await this.prisma.student.update({
  //     where: { email },
  //     data: { password: hashedNewPassword },
  //   });

  //   const emailBody = `Hello ${student.name},\n\nYour password has been successfully reset.\n\nIf you did not request this change, please contact support immediately.\n\nThank you!`;
  //   const emailSent = await this.emailService.sendMail(email, 'Password Reset Successful', emailBody);
  //   if (!emailSent) {
  //     throw new Error('Failed to send password reset confirmation email');
  //   }

  //   return { message: 'Password reset successfully' };
  // }


  // Change password with old password validation
  async changePassword(email: string, oldPassword: string, newPassword: string, confirmPassword: string) {
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('New password and confirm password do not match');
    }

    const student = await this.prisma.student.findUnique({ where: { email } });
    if (!student) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isOldPasswordValid = await bcrypt.compare(oldPassword, student.password);
    if (!isOldPasswordValid) {
      throw new UnauthorizedException('Invalid old password');
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    await this.prisma.student.update({
      where: { email },
      data: { password: hashedNewPassword },
    });

    const emailBody = `Hello ${student.name},\n\nYour password has been successfully changed. If you did not request this change, please contact support immediately.\n\nThank you!`;
    const emailSent = await this.emailService.sendMail(student.email, 'Password Change Successful', emailBody);
    if (!emailSent) {
      throw new Error('Failed to send password change confirmation email');
    }

    return { message: 'Password changed successfully' };
  }

  

  // async changePassword(email: string, currentPassword: string, newPassword: string) {
  //   const student = await this.prisma.student.findUnique({ where: { email } });
  //   if (!student) {
  //     throw new UnauthorizedException('Invalid email');
  //   }

  //   const isPasswordValid = await bcrypt.compare(currentPassword, student.password);
  //   if (!isPasswordValid) {
  //     throw new UnauthorizedException('Invalid current password');
  //   }

  //   const hashedPassword = await bcrypt.hash(newPassword, 10);

  //   await this.prisma.student.update({
  //     where: { email },
  //     data: { password: hashedPassword },
  //   });

  //   return { message: 'Password changed successfully' };
  // }



  async forgotPassword(email: string) {
    const student = await this.prisma.student.findUnique({ where: { email } });
    if (!student) {
      throw new BadRequestException('Email not found');
    }

    const resetToken = uuidv4(); // Generate a unique reset token
    // const resetTokenExpiry = new Date(Date.now() + 300000); // Set expiry time (5 minutes)

    const resetTokenExpiry = new Date(Date.now() + 120000); // Set expiry time (2 minutes)

    await this.prisma.student.update({
      where: { email },
      data: { resetToken, resetTokenExpiry },
    });

    const resetLink = `http://localhost:3000/auth/reset-password?token=${resetToken}`; // Replace with your frontend URL

    const emailBody = `Hello ${student.name},\n\nPlease use the following link to reset your password. This link will expire in 5 minutes:\n\n${resetLink}\n\nIf you did not request a password reset, please ignore this email.\n\nThank you!`;
    const emailSent = await this.emailService.sendMail(email, 'Password Reset Request', emailBody);
    if (!emailSent) {
      throw new Error('Failed to send password reset email');
    }

    return { message: 'Password reset token sent' };
  }

  async resetPasswordWithToken(token: string, newPassword: string, confirmPassword: string) {
    if (newPassword !== confirmPassword) {
      throw new BadRequestException('New password and confirm password do not match');
    }

    const student = await this.prisma.student.findFirst({ where: { resetToken: token, resetTokenExpiry: { gte: new Date() } } });

    if (!student) {
      throw new BadRequestException('Invalid or expired token');
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    await this.prisma.student.update({
      where: { email: student.email },
      data: { password: hashedNewPassword, resetToken: null, resetTokenExpiry: null },
    });

    const emailBody = `Hello ${student.name},\n\nYour password has been successfully reset. If you did not request this change, please contact support immediately.\n\nThank you!`;
    const emailSent = await this.emailService.sendMail(student.email, 'Password Reset Successful', emailBody);
    if (!emailSent) {
      throw new Error('Failed to send password reset confirmation email');
    }

    return { message: 'Password reset successfully' };
  }



  async resendOtp(email: string) {
    const student = await this.prisma.student.findUnique({ where: { email } });
    if (!student) {
      throw new BadRequestException('Invalid email');
    }

    const otp = generateOTP();
    await this.prisma.student.update({
      where: { email },
      data: { otp },
    });

    const emailBody = `Hello ${student.name},\n\nHere is your OTP for email verification: ${otp}\n\nPlease use this OTP to verify your email.\n\nThank you!`;
    const emailSent = await this.emailService.sendMail(email, 'Resend OTP for Email Verification', emailBody);
    if (!emailSent) {
      throw new Error('Failed to send OTP email');
    }

    return { message: 'OTP sent successfully' };
  }
// Get user profile
async getProfile(email: string): Promise<any> {
  const user = await this.prisma.student.findUnique({ where: { email } });
  if (!user) {
    throw new NotFoundException('Student not found');
  }
  // Return only the necessary fields from the user object
  return {
    email: user.email,
    name: user.name,
    password: user.password,
    isVerified: user.isVerified,
  };
}

// // Get user profile
// async getProfile(email: string): Promise<User> {
//   const user = this.users.find(user => user.email === email);
//   if (!user) {
//     throw new NotFoundException('User not found');
//   }
//   return user;
// }

// Update user profile
async updateProfile(email: string, name: string): Promise<any> {
  const user = this.users.find(user => user.email === email);
  if (!user) {
    throw new NotFoundException('Student not found');
  }

  user.name = name;
  return user;
}

// Partially update user profile
async partialUpdateProfile(email: string, name: string): Promise<any> {
  return this.updateProfile(email, name); // Simplified for example
}

// Delete user profile
async deleteProfile(email: string): Promise<{ message: string }> {
  const user = await this.prisma.student.findUnique({ where: { email } });
  if (!user) {
    throw new NotFoundException('Student not found');
  }

  await this.prisma.student.delete({ where: { email } });
  return { message: 'Profile deleted successfully' };
}


async getById(id: string): Promise<any> {
  const numericId = parseInt(id, 10); // Convert id to number
  const student = await this.prisma.student.findUnique({ where: { id: numericId } });

  if (!student) {
    throw new NotFoundException(`Student with ID ${id} not found`);
  }

  return student;
}

async getAllStudents(): Promise<any[]> {
  return this.prisma.student.findMany();
}





// async updateUser(id: number, updateUserDto: UpdateUserDto): Promise<any> {
//   const user = this.users.find((user, index) => index === id);
//   if (!user) {
//     throw new NotFoundException('User not found');
//   }

//   const { email, password, name } = updateUserDto;

//   if (email) {
//     user.email = email;
//   }
//   if (password) {
//     user.password = `hashed-${password}`; // Hash the password
//   }
//   if (name) {
//     user.name = name;
//   }

//   return user;
// }

async update(id: string, updateUserDto: UpdateUserDto): Promise<any> {
  const user = await this.prisma.student.update({
    where: { id: parseInt(id, 10) },
    data: updateUserDto,
  });
  return user;
}

}
