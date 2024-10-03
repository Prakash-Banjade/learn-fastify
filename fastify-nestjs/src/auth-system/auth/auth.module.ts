import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { ImagesModule } from 'src/file-management/images/images.module';
import { AccountsModule } from '../accounts/accounts.module';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: process.env.ACCESS_TOKEN_SECRET!,
      signOptions: { expiresIn: process.env.ACCESS_TOKEN_EXPIRATION! },
    }),
    AccountsModule,
    UsersModule,
    ImagesModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
  ]
})
export class AuthModule { }
