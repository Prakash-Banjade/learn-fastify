import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ImagesModule } from 'src/file-management/images/images.module';
import { AccountsModule } from '../accounts/accounts.module';
import { UsersModule } from '../users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { AuthHelper } from './helpers/auth.helper';

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: process.env.ACCESS_TOKEN_SECRET!,
      signOptions: { expiresIn: process.env.ACCESS_TOKEN_EXPIRATION_MS! },
    }),
    AccountsModule,
    UsersModule,
    ImagesModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthHelper,
  ]
})
export class AuthModule { }
