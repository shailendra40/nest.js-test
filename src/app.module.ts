// //src/app.module.ts

// import { Module } from '@nestjs/common';
// import { AppController } from './app.controller';
// import { AppService } from './app.service';
// import { AuthModule } from './auth/auth.module';

// @Module({
//   imports: [AuthModule],
//   controllers: [AppController],
//   providers: [AppService],
// })
// export class AppModule {}


// // src/app.module.ts

// import { Module } from '@nestjs/common';
// import { AppController } from './app.controller';
// import { AppService } from './app.service';
// import { AuthModule } from './auth/auth.module';
// import { PrismaModule } from './prisma/prisma';
// import { ConfigModule } from '@nestjs/config';

// @Module({
//   imports: [ ConfigModule.forRoot({isGlobal: true,}), AuthModule, PrismaModule],
//   // controllers: [AppController],
//   // providers: [AppService],
// })
// export class AppModule {}


// src/app.module.ts

import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
// import { PrismaModule } from './prisma/prisma.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    AuthModule,
    // PrismaModule,
  ],
})
export class AppModule {}

