// src/auth/dto/update-user.dto.ts

import { IsEmail, IsOptional, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

// export class UpdateUserDto {
//   @IsOptional()
//   @IsEmail()
//   email?: string;

//   @IsOptional()
//   @IsString()
//   @MinLength(6)
//   password?: string;

//   @IsOptional()
//   @IsString()
//   name?: string;
// }


export class UpdateUserDto {
  @ApiProperty({ description: 'The name of the user', required: false })
  @IsOptional()
  @IsString()
  readonly name?: string;

  // Add other properties as needed
}