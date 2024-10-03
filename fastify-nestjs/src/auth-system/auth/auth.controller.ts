import { Body, Controller, HttpCode, HttpStatus, Post, Req, Res, UnauthorizedException, UseGuards, UseInterceptors } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignInDto } from './dto/signIn.dto';
import { RegisterDto } from './dto/register.dto';
import { ApiBearerAuth, ApiConsumes, ApiTags } from '@nestjs/swagger';
import { FormDataRequest } from 'nestjs-form-data';
import { PasswordChangeRequestDto } from './dto/password-change-req.dto';
import { ResetPasswordDto } from './dto/resetPassword.dto';
import { EmailVerificationDto } from './dto/email-verification.dto';
import { RefreshTokenGuard } from '../../common/guards/refresh-token.guard';
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

    refresshCookieOptions: CookieSerializeOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 day
    }

    accessCookieOptions: CookieSerializeOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        maxAge: 15 * 60 * 1000, // 15 min
    }

    //     private readonly ACCESS_TOKEN_KEY = 'access_token';
    //     private readonly REFRESH_TOKEN_KEY = 'refresh_token';
    //     private readonly REFRESH_HEADER_KEY = process.env.REFRESH_HEADER_KEY

    //     @Public()
    //     @HttpCode(HttpStatus.OK)
    //     @Post('login')
    //     @ApiConsumes('multipart/form-data')
    //     @FormDataRequest()
    //     async signIn(@Body() signInDto: SignInDto, @Res({ passthrough: true }) reply: FastifyReply, @Req() req: Request) {
    //         const { access_token, new_refresh_token, payload } = await this.authService.signIn(signInDto, req, reply, this.refresshCookieOptions);

    //         res.cookie(this.ACCESS_TOKEN_KEY, access_token, this.refresshCookieOptions);
    //         res.cookie(this.REFRESH_TOKEN_KEY, new_refresh_token, this.refresshCookieOptions);
    //         res.set(this.REFRESH_HEADER_KEY, `${new_refresh_token}`);

    //         return { access_token, refresh_token: new_refresh_token, payload };
    //     }

    //     // @Public()
    //     // @Post('googleOAuthLogin')
    //     // @HttpCode(HttpStatus.OK)
    //     // @ApiConsumes('multipart/form-data')
    //     // @UseInterceptors(TransactionInterceptor)
    //     // async googleOAuthLogin(@Body() googleOAuthDto: GoogleOAuthDto, @Res({ passthrough: true }) res: Response, @Req() req: Request) {
    //     //     const { access_token, new_refresh_token, payload } = await this.authService.googleOAuthLogin(googleOAuthDto, req, res, this.refresshCookieOptions);

    //     //     res.cookie(this.ACCESS_TOKEN_KEY, access_token, this.refresshCookieOptions);
    //     //     res.cookie(this.REFRESH_TOKEN_KEY, new_refresh_token, this.refresshCookieOptions);
    //     //     res.set(this.REFRESH_HEADER_KEY, `${new_refresh_token}`);

    //     //     return { access_token, refresh_token: new_refresh_token, payload };
    //     // }

    //     @Public()
    //     @Post('refresh')
    //     @HttpCode(HttpStatus.OK)
    //     @ApiConsumes('multipart/form-data')
    //     @UseInterceptors(TransactionInterceptor)
    //     @UseGuards(RefreshTokenGuard)
    //     @FormDataRequest()
    //     async refreshToken(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    //         const refresh_token = req.cookies?.refresh_token;
    //         if (!refresh_token) throw new UnauthorizedException();

    //         res.clearCookie(this.ACCESS_TOKEN_KEY, this.accessCookieOptions); // CLEAR COOKIE, BCZ A NEW ONE IS TO BE GENERATED
    //         res.clearCookie(this.REFRESH_TOKEN_KEY, this.refresshCookieOptions); // CLEAR COOKIE, BCZ A NEW ONE IS TO BE GENERATED
    //         res.removeHeader(this.REFRESH_HEADER_KEY);

    //         const { new_access_token, new_refresh_token, payload } = await this.authService.refresh(refresh_token);

    //         res.cookie(this.ACCESS_TOKEN_KEY, new_access_token, this.accessCookieOptions);
    //         res.cookie(this.REFRESH_TOKEN_KEY, new_refresh_token, this.refresshCookieOptions);
    //         res.set(this.REFRESH_HEADER_KEY, `${new_refresh_token}`);

    //         return { access_token: new_access_token, refresh_token: new_refresh_token, payload };
    //     }

    //     @Public()
    //     @Post('register')
    //     @ApiConsumes('multipart/form-data')
    //     @FormDataRequest()
    //     @UseInterceptors(TransactionInterceptor)
    //     async register(@Body() registerDto: RegisterDto) {
    //         return await this.authService.register(registerDto);
    //     }

    //     @Public()
    //     @Post('verifyEmail')
    //     @ApiConsumes('multipart/form-data')
    //     @FormDataRequest()
    //     @UseInterceptors(TransactionInterceptor)
    //     async verifyEmail(@Body() emailVerificationDto: EmailVerificationDto) {
    //         return await this.authService.verifyEmail(emailVerificationDto);
    //     }

    //     @ApiBearerAuth()
    //     @Post('logout')
    //     @UseInterceptors(TransactionInterceptor)
    //     @UseGuards(RefreshTokenGuard)
    //     @HttpCode(HttpStatus.NO_CONTENT)
    //     async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response) {
    //         // on client also delete the access_token

    //         const refresh_token = req.cookies?.refresh_token;
    //         if (!refresh_token) return res.sendStatus(204)

    //         await this.authService.logout(refresh_token);

    //         res.clearCookie(this.ACCESS_TOKEN_KEY, this.accessCookieOptions);
    //         res.clearCookie(this.REFRESH_TOKEN_KEY, this.refresshCookieOptions);
    //         res.removeHeader(this.REFRESH_HEADER_KEY);
    //         return;
    //     }

    //     @ApiBearerAuth()
    //     @Post('changePassword')
    //     @HttpCode(HttpStatus.OK)
    //     @UseInterceptors(TransactionInterceptor)
    //     async changePassword(@Body() changePasswordDto: ChangePasswordDto, @CurrentUser() currentUser: AuthUser) {
    //         return await this.authService.changePassword(changePasswordDto, currentUser);
    //     }

    //     @Public()
    //     @Post('forgetPassword')
    //     @HttpCode(HttpStatus.OK)
    //     // @Throttle({ default: { limit: 1, ttl: 5000 } }) // override the default rate limit for password reset
    //     forgetPassword(@Body() { email, cms }: PasswordChangeRequestDto) {
    //         return this.authService.forgetPassword(email, cms)
    //     }

    //     @Public()
    //     @Post('verifyResetToken')
    //     @HttpCode(HttpStatus.OK)
    //     // @Throttle({ default: { limit: 1, ttl: 5000 } }) // override the default rate limit for password reset
    //     verifyResetToken(@Body() { token }: VerifyResetTokenDto) {
    //         return this.authService.verifyResetToken(token)
    //     }

    //     @Public()
    //     @Post('resetPassword')
    //     @HttpCode(HttpStatus.OK)
    //     // @Throttle({ default: { limit: 1, ttl: 5000 } }) // override the default rate limit for password reset
    //     resetPassword(@Body() { password, token }: ResetPasswordDto) {
    //         return this.authService.resetPassword(password, token);
    //     }
}
