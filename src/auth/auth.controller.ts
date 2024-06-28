// src/auth/auth.controller.ts

import { Body, Controller, Get, Post, Put, Patch, Delete, UseGuards, BadRequestException, Req, Param, NotFoundException  } from '@nestjs/common';
import { AuthService } from './auth.service';
// import { AuthService, User } from './auth.service';
import { JwtAuthGuard } from './jwt-auth.guard';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiBearerAuth } from '@nestjs/swagger';
import { RegisterDto } from './dto/register.dto';
import { UpdateUserDto } from './dto/update-user.dto';
// import { PublicGuard } from './guards/public.guard'; // Import the custom guard
// import { PrivateGuard } from './guards/private.guard'; // Import the custom guards


@ApiTags('auth')
@Controller('auth')
// @Controller('profile')
export class AuthController {
  RegisterDto: any;
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @ApiOperation({ summary: 'Register a new student' })
  @ApiResponse({ status: 201, description: 'Student registered successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'pydv1415@gmail.com' },
        password: { type: 'string', example: 'password' },
        name: { type: 'string', example: 'Shailendra Ydv' },
      },
    },
  })
  async register(@Body() body: { email: string; password: string; name: string }) {
    return this.authService.register(body.email, body.password, body.name);
  }

  @Post('verify-email')
  @ApiOperation({ summary: 'Verify email with OTP' })
  @ApiResponse({ status: 200, description: 'Email verified successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'pydv1415@gmail.com' },
        otp: { type: 'string', example: '123456' },
      },
    },
  })
  async verifyEmail(@Body() body: { email: string; otp: string }) {
    if (!body.email || !body.otp) {
      throw new BadRequestException('Email and OTP are required');
    }
    return this.authService.verifyEmail(body.email, body.otp);
  }

  @Post('login')
  @ApiOperation({ summary: 'Login as a student' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'pydv1415@gmail.com' },
        password: { type: 'string', example: 'password' },
      },
    },
  })
// async login(@Body() body: { email: string; password: string }) {
//     const student = await this.authService.validateStudent(body.email, body.password);
//     if (student === undefined) {
//         return { message: 'Invalid credentials' };
//     }
//     // return this.authService.login(student);
//     return this.authService.login(body.email, body.password);
// }

async login(@Body() body: { email: string; password: string }) {
  if (!body.email || !body.password) {
    throw new BadRequestException('Email and password are required');
  }
  return this.authService.login(body.email, body.password);
}

  // @Post('logout')
  // @UseGuards(JwtAuthGuard)
  // @ApiBearerAuth()
  // @ApiOperation({ summary: 'Logout a student' })
  // async logout(@Req() req) {
  //   // You can implement token invalidation logic here if needed
  //   return { message: 'Logout successful' };
  // }


  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Logout a student' })
  async logout(@Req() req) {
  const token = req.headers.authorization.split(' ')[1]; // Extract JWT token from Authorization header
  await this.authService.logout(token);
  return { message: 'Logout successful' };
}


// @Post('logout')
//   @UseGuards(JwtAuthGuard)
//   @ApiBearerAuth()
//   @ApiOperation({ summary: 'Logout a student' })
//   @ApiResponse({ status: 200, description: 'Logout successful' })
//   @ApiResponse({ status: 401, description: 'Unauthorized' })
//   async logout(@Req() req) {
//     const token = req.headers.authorization.split(' ')[1]; // Extract JWT token from Authorization header
//     await this.authService.logout(token);
//     return { message: 'Logout successful' };
//   }


// Here, we have added a new endpoint to handle password reset requests. The reset-password-request endpoint sends an email to the user with a password reset link. The reset-password endpoint resets the password using the token sent in the email and the new password provided by the user.

// // Here only new password reset don't validate old password.
// @Post('reset-password-request')
//   @ApiOperation({ summary: 'Request a password reset' })
//   @ApiResponse({ status: 200, description: 'Password reset email sent' })
//   @ApiResponse({ status: 400, description: 'Bad Request' })
//   @ApiBody({
//     schema: {
//       type: 'object',
//       properties: {
//         email: { type: 'string', example: 'pydv1415@gmail.com' },
//       },
//     },
//   })
//   async resetPasswordRequest(@Body() body: { email: string }) {
//     if (!body.email) {
//       throw new BadRequestException('Email is required');
//     }
//     return this.authService.sendPasswordResetEmail(body.email);
//   }


//   @Post('reset-password')
//   @ApiOperation({ summary: 'Reset password using token' })
//   @ApiResponse({ status: 200, description: 'Password reset successful' })
//   @ApiResponse({ status: 400, description: 'Bad Request' })
//   @ApiBody({
//     schema: {
//       type: 'object',
//       properties: {
//         token: { type: 'string', example: 'reset-token' },
//         newPassword: { type: 'string', example: 'newpassword' },
//       },
//     },
//   })
//   async resetPassword(@Body() body: { token: string; newPassword: string }) {
//     if (!body.token || !body.newPassword) {
//       throw new BadRequestException('Token and new password are required');
//     }
//     return this.authService.resetPassword(body.token, body.newPassword);
//   }



// // Here reset password with old password validation.
// @Post('reset-password')
// // @Post('reset-password-request')
//   @UseGuards(JwtAuthGuard)
//   @ApiBearerAuth()
//   @ApiOperation({ summary: 'Reset password with old password validation' })
//   @ApiResponse({ status: 200, description: 'Password reset successfully' })
//   @ApiResponse({ status: 400, description: 'Bad Request' })
//   @ApiBody({
//     schema: {
//       type: 'object',
//       properties: {
//         oldPassword: { type: 'string', example: 'password' },
//         newPassword: { type: 'string', example: 'password1' },
//         confirmPassword: { type: 'string', example: 'password1' },
//       },
//     },
//   })
//   async resetPassword(@Req() req, @Body() body: { oldPassword: string; newPassword: string; confirmPassword: string }) {
//     if (!body.oldPassword || !body.newPassword || !body.confirmPassword) {
//       throw new BadRequestException('Old password, new password, and confirm password are required');
//     }
//     if (body.newPassword !== body.confirmPassword) {
//       throw new BadRequestException('New password and confirm password do not match');
//     }
//     return this.authService.resetPassword(req.user.email, body.oldPassword, body.newPassword);
//   }



//   @Post('forgot-password')
//   @ApiOperation({ summary: 'Request a password reset token' })
//   @ApiResponse({ status: 200, description: 'Password reset token sent' })
//   @ApiResponse({ status: 400, description: 'Bad Request' })
//   @ApiBody({
//     schema: {
//       type: 'object',
//       properties: {
//         email: { type: 'string', example: 'pydv1415@gmail.com' },
//       },
//     },
//   })
//   async forgotPassword(@Body() body: { email: string }) {
//     if (!body.email) {
//       throw new BadRequestException('Email is required');
//     }
//     return this.authService.forgotPassword(body.email);
//   }

//   @Post('reset-password-token')
//   @ApiOperation({ summary: 'Reset password with token' })
//   @ApiResponse({ status: 200, description: 'Password reset successfully' })
//   @ApiResponse({ status: 400, description: 'Bad Request' })
//   @ApiBody({
//     schema: {
//       type: 'object',
//       properties: {
//         token: { type: 'string', example: 'resetToken' },
//         newPassword: { type: 'string', example: 'newPassword' },
//         confirmPassword: { type: 'string', example: 'newPassword' },
//       },
//     },
//   })
//   async resetPasswordWithToken(@Body() body: { token: string; newPassword: string; confirmPassword: string }) {
//     if (!body.token || !body.newPassword || !body.confirmPassword) {
//       throw new BadRequestException('Token, new password, and confirm password are required');
//     }
//     if (body.newPassword !== body.confirmPassword) {
//       throw new BadRequestException('New password and confirm password do not match');
//     }
//     return this.authService.resetPasswordWithToken(body.token, body.newPassword, body.confirmPassword);
//   }




@Post('forgot-password')
  @ApiOperation({ summary: 'Request a password reset token' })
  @ApiResponse({ status: 200, description: 'Password reset token sent' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'pydv1415@gmail.com' },
      },
    },
  })
  async forgotPassword(@Body() body: { email: string }) {
    if (!body.email) {
      throw new BadRequestException('Email is required');
    }
    return this.authService.forgotPassword(body.email);
  }

  @Post('reset-password-token')
  @ApiOperation({ summary: 'Reset password with token' })
  @ApiResponse({ status: 200, description: 'Password reset successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: { type: 'string', example: 'resetToken' },
        newPassword: { type: 'string', example: 'password1' },
        confirmPassword: { type: 'string', example: 'password1' },
      },
    },
  })
  async resetPasswordWithToken(@Body() body: { token: string; newPassword: string; confirmPassword: string }) {
    if (!body.token || !body.newPassword || !body.confirmPassword) {
      throw new BadRequestException('Token, new password, and confirm password are required');
    }
    if (body.newPassword !== body.confirmPassword) {
      throw new BadRequestException('New password and confirm password do not match');
    }
    return this.authService.resetPasswordWithToken(body.token, body.newPassword, body.confirmPassword);
  }

  @Post('change-password')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Change password with old password validation' })
  @ApiResponse({ status: 200, description: 'Password changed successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        oldPassword: { type: 'string', example: 'password' },
        newPassword: { type: 'string', example: 'password1' },
        confirmPassword: { type: 'string', example: 'password1' },
      },
    },
  })
  // async changePassword(@Req() req, @Body() body: { email: string; oldPassword: string; newPassword: string; confirmPassword: string }) {
  async changePassword(@Req() req, @Body() body: { oldPassword: string; newPassword: string; confirmPassword: string }) {
    if (!body.oldPassword || !body.newPassword || !body.confirmPassword) {
      throw new BadRequestException('Old password, new password, and confirm password are required');
    }
    if (body.newPassword !== body.confirmPassword) {
      throw new BadRequestException('New password and confirm password do not match');
    }
    // return this.authService.changePassword(body.email, body.oldPassword, body.newPassword, body.confirmPassword);
    return this.authService.changePassword(req.user.email, body.oldPassword, body.newPassword, body.confirmPassword);
  }

  @Post('resend-otp')
  @ApiOperation({ summary: 'Resend OTP for email verification' })
  @ApiResponse({ status: 200, description: 'OTP sent successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: { type: 'string', example: 'pydv1415@gmail.com' },
      },
    },
  })
  async resendOtp(@Body() body: { email: string }) {
    if (!body.email) {
      throw new BadRequestException('Email is required');
    }
    return this.authService.resendOtp(body.email);
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get Student profile' })
  @ApiResponse({ status: 200, description: 'Student profile retrieved successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getProfile(@Req() req) {
    try {
      // console.log("PROFILE=============================>", req.user.email);
      const profile = await this.authService.getProfile(req.user.email);
      return profile;
    } catch (error) {
      console.error('Error fetching profile:', error);
      throw new NotFoundException('Student profile not found');
    }
  }
  











  @Put('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update student profile' })
  @ApiResponse({ status: 200, description: 'Profile updated successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'John Doe' },
      },
    },
  })
  async updateProfile(@Req() req, @Body() body: { name: string }) {
    return this.authService.updateProfile(req.user.email, body.name);
  }

  @Patch('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Partially update student profile' })
  @ApiResponse({ status: 200, description: 'Profile partially updated successfully' })
  @ApiResponse({ status: 400, description: 'Bad Request' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'John Doe' },
      },
    },
  })
  async partialUpdateProfile(@Req() req, @Body() body: { name: string }) {
    return this.authService.partialUpdateProfile(req.user.email, body.name);
  }

  @Delete('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Delete student profile' })
  @ApiResponse({ status: 200, description: 'Profile deleted successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async deleteProfile(@Req() req) {
    return this.authService.deleteProfile(req.user.email);
  }

  // @Get('/students')
  // @ApiOperation({ summary: 'Get student profile All' })
  // async getAllStudents(): Promise<any[]> {
  //   return this.authService.getAllStudents();
  // }
  // @Get(':id')
  @Get('/students/:id')
  @ApiOperation({ summary: 'Get student profile By Id' })
  async getStudentById(@Param('id') id: string): Promise<any> {
    try {
      const student = await this.authService.getById(id);
      return { success: true, data: student };
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw new NotFoundException(error.message);
      } else { 
        throw error;
      }
    }
  }

  @Get('/students')
  @ApiOperation({ summary: 'Get student profile All' })
  async getAllStudents(): Promise<any[]> {
    return this.authService.getAllStudents();
  }




  // @Put('/students/:id') // Change the route decorator to use '/students/:id'
  // async updateStudentById(@Param('id') id: string, @Body() updateData: any): Promise<any> {
  //   return this.authService.updateById(id, updateData);
  // }

  // @Get(':id')
  // async findOne(@Param('id') id: string): Promise<any> {
  //   return this.authService.findOne(id);
  // }

  // @Put(':id')
  // async update(@Param('id') id: string, @Body() UpdateUserDto: UpdateUserDto): Promise<any> {
  //   return this.RegisterDto.update(id, UpdateUserDto);
  // }

  @Put(':id')
  @UseGuards(JwtAuthGuard)
  // @UseGuards(PublicGuard) // Apply the custom guard to this route
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Update user by ID' })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        name: { type: 'string', example: 'John Doe' },
        // Add other properties as needed with examples
      },
    },
  })
  async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto): Promise<any> {
    return this.authService.update(id, updateUserDto);
  }
  


















  // // Public update route (no authorization required)
  // @UseGuards(PublicGuard)
  // @Put('public-update/:id')
  // async publicUpdate(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto): Promise<any> {
  //   try {
  //     return await this.authService.update(id, updateUserDto);
  //   } catch (error) {
  //     if (error instanceof NotFoundException) {
  //       throw new NotFoundException(error.message);
  //     } else {
  //       throw error;
  //     }
  //   }
  // }

  // // Private update route (authorization required)
  // @UseGuards(PrivateGuard)
  // @Put('private-update/:id')
  // async privateUpdate(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto, @Req() req): Promise<any> {
  //   try {
  //     const user = req.user; // Authorized user information
  //     return await this.authService.update(id, updateUserDto);
  //   } catch (error) {
  //     if (error instanceof NotFoundException) {
  //       throw new NotFoundException(error.message);
  //     } else {
  //       throw error;
  //     }
  //   }
  // }




}
