import {
  Inject,
  Injectable,
  Scope,
  UnauthorizedException,
} from '@nestjs/common';
import { DataSource } from 'typeorm';
import { PasswordChangeRequest } from './entities/password-change-request.entity';
import { EmailVerificationPending } from './entities/email-verification-pending.entity';
import { BaseRepository } from 'src/common/repository/base-repository';
import { REQUEST } from '@nestjs/core';
import { FastifyReply, FastifyRequest } from 'fastify';
import { Account } from '../accounts/entities/account.entity';
import { User } from '../users/entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { AuthUser } from 'src/common/types/global.type';
import { CookieSerializeOptions } from '@fastify/cookie';
import { Tokens } from 'src/common/CONSTANTS';
import { RegisterDto } from './dto/register.dto';
import { SignInDto } from './dto/signIn.dto';
import { MailService } from 'src/mail/mail.service';
import { AuthHelper } from './helpers/auth.helper';

@Injectable({ scope: Scope.REQUEST })
export class AuthService extends BaseRepository {
  constructor(
    private readonly datasource: DataSource,
    @Inject(REQUEST) req: FastifyRequest,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly mailService: MailService,
    private readonly authHelper: AuthHelper,
  ) { super(datasource, req) }

  private readonly accountsRepo = this.datasource.getRepository<Account>(Account)
  private readonly usersRepo = this.datasource.getRepository<User>(User)
  private readonly emailVerificationPendingRepo = this.datasource.getRepository<EmailVerificationPending>(EmailVerificationPending)
  private readonly passwordChangeRequestRepo = this.datasource.getRepository<PasswordChangeRequest>(PasswordChangeRequest);
  private readonly ACCESS_TOKEN_SECRET = this.configService.getOrThrow<string>('ACCESS_TOKEN_SECRET');
  private readonly ACCESS_TOKEN_EXPIRATION_MS = this.configService.getOrThrow<string>('ACCESS_TOKEN_EXPIRATION_MS');
  private readonly REFRESH_TOKEN_SECRET = this.configService.getOrThrow<string>('REFRESH_TOKEN_SECRET');
  private readonly REFRESH_TOKEN_EXPIRATION_MS = this.configService.getOrThrow<string>('REFRESH_TOKEN_EXPIRATION_MS');

  async login(signInDto: SignInDto, req: FastifyRequest, reply: FastifyReply) {
    const existingRefreshToken = req.cookies?.refresh_token;

    const foundAccount = await this.authHelper.validateAccount(signInDto.email, signInDto.password);
    if (!foundAccount.isVerified) return await this.authHelper.sendConfirmationEmail(foundAccount);

    const payload: AuthUser = {
      email: foundAccount.email,
      accountId: foundAccount.id,
      userId: foundAccount.user.id,
      role: foundAccount.role,
    };

    const access_token = await this.createAccessToken(payload);
    const refresh_token = await this.createRefreshToken(payload);

    const newRefreshTokenArray = !refresh_token ? (foundAccount.refreshTokens ?? []) : (foundAccount?.refreshTokens?.filter((rt) => rt !== existingRefreshToken) ?? [])
    if (refresh_token) reply.clearCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, this.getCookieOptions(Tokens.REFRESH_TOKEN_COOKIE_NAME)); // CLEAR COOKIE, BCZ A NEW ONE IS TO BE GENERATED

    foundAccount.refreshTokens = [...newRefreshTokenArray, refresh_token];

    reply.setCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, refresh_token, this.getCookieOptions(Tokens.REFRESH_TOKEN_COOKIE_NAME))

    await this.accountsRepo.save(foundAccount);

    return { access_token };
  }

  async createAccessToken(payload: AuthUser): Promise<string> {
    return await this.jwtService.signAsync(payload, {
      secret: this.ACCESS_TOKEN_SECRET,
      expiresIn: this.ACCESS_TOKEN_EXPIRATION_MS,
    });
  }

  async createRefreshToken(payload: Pick<AuthUser, 'accountId'>): Promise<string> {
    return await this.jwtService.signAsync(
      { accountId: payload.accountId },
      {
        secret: this.REFRESH_TOKEN_SECRET,
        expiresIn: this.REFRESH_TOKEN_EXPIRATION_MS,
      },
    );
  }

  private getCookieOptions(tokenType: Tokens.ACCESS_TOKEN_COOKIE_NAME | Tokens.REFRESH_TOKEN_COOKIE_NAME): CookieSerializeOptions {
    const cookieOptions: CookieSerializeOptions = {
      httpOnly: true,
      secure: this.configService.getOrThrow('NODE_ENV') === 'production',
      sameSite: 'strict',
      maxAge: tokenType === Tokens.ACCESS_TOKEN_COOKIE_NAME ? Number(this.ACCESS_TOKEN_EXPIRATION_MS) : Number(this.REFRESH_TOKEN_EXPIRATION_MS),
    };

    return cookieOptions;
  }

  async register(registerDto: RegisterDto) {
    const account = this.accountsRepo.create(registerDto);
    return await this.accountsRepo.save(account);
  }


}
