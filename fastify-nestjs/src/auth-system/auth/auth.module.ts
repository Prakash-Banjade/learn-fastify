import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ImagesModule } from 'src/file-management/images/images.module';
import { AccountsModule } from '../accounts/accounts.module';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [
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
