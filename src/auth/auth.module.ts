// // src/auth/auth.module.ts

// import { Module } from '@nestjs/common';
// import { AuthService } from './auth.service';
// import { AuthController } from './auth.controller';
// import { JwtModule } from '@nestjs/jwt';
// import { JwtStrategy } from './jwt.strategy';
// import { PrismaService } from '../prisma.service';
// import { EmailService } from '../email/email.service';

// @Module({
//   imports: [
//     JwtModule.register({
//       secret: 'yourSecretKey', // Use a strong secret key
//       signOptions: { expiresIn: '60m' },
//     }),
//   ],
//   providers: [AuthService, JwtStrategy, PrismaService, EmailService],
//   controllers: [AuthController],
// })
// export class AuthModule {}


// src/auth/auth.module.ts

import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtStrategy } from './jwt.strategy';
import { PrismaService } from '../prisma.service';
import { EmailService } from '../email/email.service';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
  ],
  providers: [AuthService, JwtStrategy, PrismaService, EmailService],
  controllers: [AuthController],
})
export class AuthModule {}
