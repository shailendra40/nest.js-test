"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const prisma_service_1 = require("../prisma.service");
const bcrypt = require("bcrypt");
const email_service_1 = require("../email/email.service");
const otp_1 = require("../utils/otp");
const uuid_1 = require("uuid");
let AuthService = class AuthService {
    resetPassword(email, oldPassword, newPassword) {
        throw new Error('Method not implemented.');
    }
    constructor(prisma, jwtService, emailService) {
        this.prisma = prisma;
        this.jwtService = jwtService;
        this.emailService = emailService;
        this.blacklistedTokens = new Set();
    }
    async register(email, password, name) {
        try {
            if (!this.isValidEmail(email)) {
                throw new common_1.BadRequestException('Invalid email format');
            }
            const existingStudent = await this.prisma.student.findUnique({ where: { email } });
            if (existingStudent) {
                throw new Error('Email is already registered');
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            const otp = (0, otp_1.generateOTP)();
            const student = await this.prisma.student.create({
                data: {
                    email,
                    password: hashedPassword,
                    name,
                    otp,
                    isVerified: false,
                },
            });
            const emailBody = `Hello ${name},\n\nWelcome to Lala Ji Ki Hevali!\n\nYour OTP for email verification is: ${otp}\n\nPlease verify your email to complete your registration.\n\nThank you!`;
            const emailSent = await this.emailService.sendMail(email, 'Account Verification with OTP', emailBody);
            if (!emailSent) {
                throw new Error('Failed to send OTP email');
            }
            return student;
        }
        catch (error) {
            console.error('Error registering student:', error.message);
            throw new Error('Failed to register student');
        }
    }
    async verifyEmail(email, otp) {
        const student = await this.prisma.student.findUnique({ where: { email } });
        if (!student || student.otp !== otp) {
            throw new common_1.UnauthorizedException('Invalid OTP');
        }
        await this.prisma.student.update({
            where: { email },
            data: { isVerified: true, otp: null },
        });
        const emailBody = `Hello ${student.name},\n\nCongratulations! Your email has been successfully verified.\n\nYou can now log in to your account and enjoy our services.\n\nThank you for verifying your email!\n\nBest regards,\nLala Ji Ki Hevali Mai Aap Ka Swagat Hai!`;
        const emailSent = await this.emailService.sendMail(email, 'Email Verification Success', emailBody);
        if (!emailSent) {
            throw new Error('Failed to send verification email');
        }
        return { message: 'Email verified successfully' };
    }
    async validateStudent(email, password) {
        const student = await this.prisma.student.findUnique({ where: { email } });
        if (student && await bcrypt.compare(password, student.password)) {
            return student;
        }
        return null;
    }
    async login(email, password) {
        const student = await this.prisma.student.findUnique({ where: { email } });
        if (!student) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        if (!student.isVerified) {
            throw new common_1.UnauthorizedException('Your account is not verified. Please verify your email first.');
        }
        const isPasswordValid = await bcrypt.compare(password, student.password);
        if (!isPasswordValid) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        const payload = { email: student.email, sub: student.id };
        const token = this.jwtService.sign(payload);
        const emailBody = `Hello ${student.name},\n\nCongrats! You have successfully logged in to your account.\n\nIf this wasn't you, please secure your account immediately.\n\nBest regards,\nLala Ji Ki Hevali Mai Aap Ka Swagat Hai!`;
        const emailSent = await this.emailService.sendMail(email, 'Login Successful', emailBody);
        if (!emailSent) {
            throw new Error('Failed to send login confirmation email');
        }
        return {
            access_token: token,
        };
    }
    isValidEmail(email) {
        const re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@(([^<>()[\]\.,;:\s@"]+\.)+[^<>()[\]\.,;:\s@"]{2,})$/i;
        return re.test(String(email).toLowerCase());
    }
    async logout(token) {
        this.blacklistToken(token);
        return { message: 'Logout successful' };
    }
    blacklistToken(token) {
        this.blacklistedTokens.add(token);
    }
    isTokenBlacklisted(token) {
        return this.blacklistedTokens.has(token);
    }
    async sendPasswordResetEmail(email) {
        const student = await this.prisma.student.findUnique({ where: { email } });
        if (!student) {
            throw new common_1.BadRequestException('Invalid email');
        }
        const resetToken = (0, uuid_1.v4)();
        const resetTokenExpiry = new Date();
        resetTokenExpiry.setMinutes(resetTokenExpiry.getMinutes() + 5);
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
    async changePassword(email, oldPassword, newPassword, confirmPassword) {
        if (newPassword !== confirmPassword) {
            throw new common_1.BadRequestException('New password and confirm password do not match');
        }
        const student = await this.prisma.student.findUnique({ where: { email } });
        if (!student) {
            throw new common_1.UnauthorizedException('Invalid credentials');
        }
        const isOldPasswordValid = await bcrypt.compare(oldPassword, student.password);
        if (!isOldPasswordValid) {
            throw new common_1.UnauthorizedException('Invalid old password');
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
    async forgotPassword(email) {
        const student = await this.prisma.student.findUnique({ where: { email } });
        if (!student) {
            throw new common_1.BadRequestException('Email not found');
        }
        const resetToken = (0, uuid_1.v4)();
        const resetTokenExpiry = new Date(Date.now() + 120000);
        await this.prisma.student.update({
            where: { email },
            data: { resetToken, resetTokenExpiry },
        });
        const resetLink = `http://localhost:3000/auth/reset-password?token=${resetToken}`;
        const emailBody = `Hello ${student.name},\n\nPlease use the following link to reset your password. This link will expire in 5 minutes:\n\n${resetLink}\n\nIf you did not request a password reset, please ignore this email.\n\nThank you!`;
        const emailSent = await this.emailService.sendMail(email, 'Password Reset Request', emailBody);
        if (!emailSent) {
            throw new Error('Failed to send password reset email');
        }
        return { message: 'Password reset token sent' };
    }
    async resetPasswordWithToken(token, newPassword, confirmPassword) {
        if (newPassword !== confirmPassword) {
            throw new common_1.BadRequestException('New password and confirm password do not match');
        }
        const student = await this.prisma.student.findFirst({ where: { resetToken: token, resetTokenExpiry: { gte: new Date() } } });
        if (!student) {
            throw new common_1.BadRequestException('Invalid or expired token');
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
    async resendOtp(email) {
        const student = await this.prisma.student.findUnique({ where: { email } });
        if (!student) {
            throw new common_1.BadRequestException('Invalid email');
        }
        const otp = (0, otp_1.generateOTP)();
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
    async getProfile(email) {
        const user = await this.prisma.student.findUnique({ where: { email } });
        if (!user) {
            throw new common_1.NotFoundException('Student not found');
        }
        return {
            email: user.email,
            name: user.name,
            password: user.password,
            isVerified: user.isVerified,
        };
    }
    async updateProfile(email, name) {
        const user = this.users.find(user => user.email === email);
        if (!user) {
            throw new common_1.NotFoundException('Student not found');
        }
        user.name = name;
        return user;
    }
    async partialUpdateProfile(email, name) {
        return this.updateProfile(email, name);
    }
    async deleteProfile(email) {
        const user = await this.prisma.student.findUnique({ where: { email } });
        if (!user) {
            throw new common_1.NotFoundException('Student not found');
        }
        await this.prisma.student.delete({ where: { email } });
        return { message: 'Profile deleted successfully' };
    }
    async getById(id) {
        const numericId = parseInt(id, 10);
        const student = await this.prisma.student.findUnique({ where: { id: numericId } });
        if (!student) {
            throw new common_1.NotFoundException(`Student with ID ${id} not found`);
        }
        return student;
    }
    async getAllStudents() {
        return this.prisma.student.findMany();
    }
    async update(id, updateUserDto) {
        const user = await this.prisma.student.update({
            where: { id: parseInt(id, 10) },
            data: updateUserDto,
        });
        return user;
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [prisma_service_1.PrismaService,
        jwt_1.JwtService,
        email_service_1.EmailService])
], AuthService);
//# sourceMappingURL=auth.service.js.map