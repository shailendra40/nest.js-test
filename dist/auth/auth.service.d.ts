import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma.service';
import { EmailService } from '../email/email.service';
import { UpdateUserDto } from './dto/update-user.dto';
export declare class AuthService {
    private readonly prisma;
    private readonly jwtService;
    private readonly emailService;
    users: any;
    findOne: any;
    resetPassword(email: any, oldPassword: string, newPassword: string): void;
    private blacklistedTokens;
    constructor(prisma: PrismaService, jwtService: JwtService, emailService: EmailService);
    register(email: string, password: string, name: string): Promise<{
        id: number;
        name: string;
        email: string;
        password: string;
        otp: string;
        resetToken: string;
        resetTokenExpiry: Date;
        isVerified: boolean;
        createdAt: Date;
        updatedAt: Date;
    }>;
    verifyEmail(email: string, otp: string): Promise<{
        message: string;
    }>;
    validateStudent(email: string, password: string): Promise<any>;
    login(email: string, password: string): Promise<{
        access_token: string;
    }>;
    private isValidEmail;
    logout(token: string): Promise<{
        message: string;
    }>;
    private blacklistToken;
    isTokenBlacklisted(token: string): boolean;
    sendPasswordResetEmail(email: string): Promise<{
        message: string;
    }>;
    changePassword(email: string, oldPassword: string, newPassword: string, confirmPassword: string): Promise<{
        message: string;
    }>;
    forgotPassword(email: string): Promise<{
        message: string;
    }>;
    resetPasswordWithToken(token: string, newPassword: string, confirmPassword: string): Promise<{
        message: string;
    }>;
    resendOtp(email: string): Promise<{
        message: string;
    }>;
    getProfile(email: string): Promise<any>;
    updateProfile(email: string, name: string): Promise<any>;
    partialUpdateProfile(email: string, name: string): Promise<any>;
    deleteProfile(email: string): Promise<{
        message: string;
    }>;
    getById(id: string): Promise<any>;
    getAllStudents(): Promise<any[]>;
    update(id: string, updateUserDto: UpdateUserDto): Promise<any>;
}
