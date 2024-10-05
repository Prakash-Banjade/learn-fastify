import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res, UnauthorizedException, UseGuards, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/signIn.dto';
import { RegisterDto } from './dto/register.dto';
import { ApiBearerAuth, ApiConsumes, ApiTags } from '@nestjs/swagger';
import { FormDataRequest } from 'nestjs-form-data';
import { PasswordChangeRequestDto } from './dto/password-change-req.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { EmailVerificationDto } from './dto/email-verification.dto';
import { ChangePasswordDto } from './dto/changePassword.dto';
import { VerifyResetTokenDto } from './dto/verify-reset-token.dto';
import { Public } from 'src/common/decorators/setPublicRoute.decorator';
import { TransactionInterceptor } from 'src/common/interceptors/transaction.interceptor';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { AuthUser } from 'src/common/types/global.type';
import { FastifyReply } from 'fastify';
import { CookieSerializeOptions } from '@fastify/cookie';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

}
