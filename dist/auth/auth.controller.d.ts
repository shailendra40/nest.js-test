import { AuthService } from './auth.service';
import { UpdateUserDto } from './dto/update-user.dto';
export declare class AuthController {
    private readonly authService;
    RegisterDto: any;
    constructor(authService: AuthService);
    register(body: {
        email: string;
        password: string;
        name: string;
    }): Promise<{
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
    verifyEmail(body: {
        email: string;
        otp: string;
    }): Promise<{
        message: string;
    }>;
    login(body: {
        email: string;
        password: string;
    }): Promise<{
        access_token: string;
    }>;
    logout(req: any): Promise<{
        message: string;
    }>;
    forgotPassword(body: {
        email: string;
    }): Promise<{
        message: string;
    }>;
    resetPasswordWithToken(body: {
        token: string;
        newPassword: string;
        confirmPassword: string;
    }): Promise<{
        message: string;
    }>;
    changePassword(req: any, body: {
        oldPassword: string;
        newPassword: string;
        confirmPassword: string;
    }): Promise<{
        message: string;
    }>;
    resendOtp(body: {
        email: string;
    }): Promise<{
        message: string;
    }>;
    getProfile(req: any): Promise<any>;
    updateProfile(req: any, body: {
        name: string;
    }): Promise<any>;
    partialUpdateProfile(req: any, body: {
        name: string;
    }): Promise<any>;
    deleteProfile(req: any): Promise<{
        message: string;
    }>;
    getStudentById(id: string): Promise<any>;
    getAllStudents(): Promise<any[]>;
    update(id: string, updateUserDto: UpdateUserDto): Promise<any>;
}
