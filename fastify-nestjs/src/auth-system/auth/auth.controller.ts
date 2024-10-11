import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res, UseGuards, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiConsumes, ApiTags } from '@nestjs/swagger';
import { FastifyReply, FastifyRequest } from 'fastify';
import { RegisterDto } from './dto/register.dto';
import { SignInDto } from './dto/signIn.dto';
import { EmailVerificationDto } from './dto/email-verification.dto';
import { Public } from 'src/common/decorators/setPublicRoute.decorator';
import { TransactionInterceptor } from 'src/common/interceptors/transaction.interceptor';
import { FormDataRequest } from 'nestjs-form-data';
import { RefreshTokenGuard } from 'src/common/guards/refresh-token.guard';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Public()
    @Post('login')
    @UseInterceptors(TransactionInterceptor)
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    async login(
        @Body() signInDto: SignInDto,
        @Req() request: FastifyRequest,
        @Res({ passthrough: true }) response: FastifyReply,
    ) {
        return this.authService.login(signInDto, request, response);
    }

    @Public()
    @Post('refresh')
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    @HttpCode(HttpStatus.OK)
    @UseGuards(RefreshTokenGuard)
    async refresh(@Req() req: FastifyRequest, @Res({ passthrough: true }) res: FastifyReply) {
        return this.authService.refresh(req, res);
    }

    @Public()
    @Post('register')
    @UseInterceptors(TransactionInterceptor)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

    @Public()
    @Post('verify-email')
    @UseInterceptors(TransactionInterceptor)
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    async verifyEmail(@Body() emailVerificationDto: EmailVerificationDto) {
        return await this.authService.verifyEmail(emailVerificationDto);
    }

    @Post('logout')
    @HttpCode(HttpStatus.OK)
    @ApiConsumes('multipart/form-data')
    @FormDataRequest()
    @UseGuards(RefreshTokenGuard)
    async logout(@Req() req: FastifyRequest, @Res({ passthrough: true }) res: FastifyReply) {
        return this.authService.logout(req, res);
    }

}
