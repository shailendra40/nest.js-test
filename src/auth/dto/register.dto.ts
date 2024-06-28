// src/auth/dto/register.dto.ts

import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsEmail, MinLength } from 'class-validator';

export class RegisterDto {
  @ApiProperty({ example: 'pydv1415@gmail.com' })
  @IsEmail()
  email: string;

  @ApiProperty({ example: 'password' })
  @IsString()
  @MinLength(6)
  password: string;

  @ApiProperty({ example: 'Shailendra Ydv' })
  @IsString()
  name: string;
}
