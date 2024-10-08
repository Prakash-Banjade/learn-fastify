import { Module } from '@nestjs/common';
import { JwtService } from './jwt.service';
import { JwtModule as Jwt } from '@nestjs/jwt';
import { APP_GUARD } from '@nestjs/core';
import { AuthGuard } from 'src/common/guards/auth.guard';

@Module({
  imports: [
    Jwt.register({
      global: true,
      secret: process.env.ACCESS_TOKEN_SECRET!,
      signOptions: { expiresIn: process.env.ACCESS_TOKEN_EXPIRATION_MS! },
    }),
  ],
  providers: [
    JwtService,
    {
      provide: APP_GUARD,
      useClass: AuthGuard, // global auth guard
    },
  ],
  exports: [JwtService],
})
export class JwtModule { }
