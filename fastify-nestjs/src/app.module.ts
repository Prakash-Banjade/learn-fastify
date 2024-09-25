import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from './datasource/typeorm.module';
import { AuthSystemModule } from './auth-system/auth-system.module';
import { FileManagementModule } from './file-management/file-management.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule,
    AuthSystemModule,
    FileManagementModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
