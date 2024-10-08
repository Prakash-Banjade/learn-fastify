import { Body, Controller, HttpCode, HttpStatus, Post, Request, Res, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiTags } from '@nestjs/swagger';
import { FastifyReply, FastifyRequest } from 'fastify';
import { RegisterDto } from './dto/register.dto';
import { SignInDto } from './dto/signIn.dto';
import { EmailVerificationDto } from './dto/email-verification.dto';
import { Public } from 'src/common/decorators/setPublicRoute.decorator';
import { TransactionInterceptor } from 'src/common/interceptors/transaction.interceptor';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Public()
    @Post('login')
    @UseInterceptors(TransactionInterceptor)
    @HttpCode(HttpStatus.OK)
    async login(
        @Body() signInDto: SignInDto,
        @Request() request: FastifyRequest,
        @Res({ passthrough: true }) response: FastifyReply,
    ) {
        return this.authService.login(signInDto, request, response);
    }

    @Public()
    @Post('register')
    @UseInterceptors(TransactionInterceptor)
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @Public()
    @Post('verify-email')
    @UseInterceptors(TransactionInterceptor)
    @HttpCode(HttpStatus.OK)
    async verifyEmail(@Body() emailVerificationDto: EmailVerificationDto) {
        return await this.authService.verifyEmail(emailVerificationDto);
    }

}
