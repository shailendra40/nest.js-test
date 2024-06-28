// // src/auth/jwt-auth.guard.ts

// import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
// import { AuthGuard } from '@nestjs/passport';
// import { AuthService } from './auth.service';

// @Injectable()
// export class JwtAuthGuard extends AuthGuard('jwt') {
//   constructor(private authService: AuthService) {
//     super();
//   }

//   canActivate(context: ExecutionContext) {
//     return super.canActivate(context);
//   }

//   handleRequest(err, user, info, context: ExecutionContext) {
//     const request = context.switchToHttp().getRequest();
//     const token = request.headers.authorization?.split(' ')[1];

//     if (this.authService.isTokenBlacklisted(token)) {
//       throw new UnauthorizedException('Token is blacklisted');
//     }

//     if (err || !user) {
//       throw err || new UnauthorizedException();
//     }
//     return user;
//   }
// }


// src/auth/jwt-auth.guard.ts

import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
