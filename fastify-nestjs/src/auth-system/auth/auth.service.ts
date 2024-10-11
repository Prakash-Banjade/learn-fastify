import {
  ConflictException,
  Inject,
  Injectable,
  NotFoundException,
  Scope,
} from '@nestjs/common';
import { DataSource } from 'typeorm';
import { PasswordChangeRequest } from './entities/password-change-request.entity';
import { EmailVerificationPending } from './entities/email-verification-pending.entity';
import { BaseRepository } from 'src/common/repository/base-repository';
import { REQUEST } from '@nestjs/core';
import { FastifyReply, FastifyRequest } from 'fastify';
import { Account } from '../accounts/entities/account.entity';
import { User } from '../users/entities/user.entity';
import { ConfigService } from '@nestjs/config';
import { AuthUser } from 'src/common/types/global.type';
import { Tokens } from 'src/common/CONSTANTS';
import { RegisterDto } from './dto/register.dto';
import { SignInDto } from './dto/signIn.dto';
import { MailService } from 'src/mail/mail.service';
import { AuthHelper } from './helpers/auth.helper';
import { JwtService } from '../jwt/jwt.service';
import { EmailVerificationDto } from './dto/email-verification.dto';
import { CookieSerializeOptions } from '@fastify/cookie';

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

  async login(signInDto: SignInDto, req: FastifyRequest, reply: FastifyReply) {
    const existingRefreshToken = req.cookies?.refresh_token;

    const foundAccount = await this.authHelper.validateAccount(signInDto.email, signInDto.password);
    if (!foundAccount.isVerified) return await this.authHelper.sendConfirmationEmail(foundAccount);

    const payload: AuthUser = {
      email: foundAccount.email,
      accountId: foundAccount.id,
      role: foundAccount.role,
    };

    const { access_token, refresh_token } = await this.jwtService.getAuthTokens(payload);

    const newRefreshTokenArray = !refresh_token ? (foundAccount.refreshTokens ?? []) : (foundAccount?.refreshTokens?.filter((rt) => rt !== existingRefreshToken) ?? [])
    if (refresh_token) reply.clearCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, this.getRefreshCookieOptions()); // CLEAR COOKIE, BCZ A NEW ONE IS TO BE GENERATED

    foundAccount.refreshTokens = [...newRefreshTokenArray, refresh_token];

    await this.accountsRepo.save(foundAccount);

    return reply
      .setCookie(Tokens.REFRESH_TOKEN_COOKIE_NAME, refresh_token, this.getRefreshCookieOptions())
      .header('Content-Type', 'application/json')
      .send({
        access_token,
      })
  }

  private getRefreshCookieOptions(): CookieSerializeOptions {
    return {
      secure: this.configService.get('NODE_ENV') === 'production',
      httpOnly: true,
      signed: true,
      sameSite: this.configService.get('NODE_ENV') === 'production' ? 'none' : 'lax',
      expires: new Date(Date.now() + (parseInt(this.configService.getOrThrow('REFRESH_TOKEN_EXPIRATION_SEC')) * 1000)),
      path: '/', // necessary to be able to access cookie from out of this route path context, like auth.guard.ts
    }
  }

  async verifyEmail(emailVerificationDto: EmailVerificationDto) {
    const foundRequest = await this.authHelper.verifyEmail(emailVerificationDto);

    // GET ACCOUNT FROM DATABASE
    const foundAccount = await this.accountsRepo.findOneBy({ email: foundRequest.email });
    if (!foundAccount) throw new NotFoundException('Account not found');

    foundAccount.isVerified = true;
    const savedAccount = await this.accountsRepo.save(foundAccount);

    const newUser = this.usersRepo.create({
      account: savedAccount,
    });

    await this.usersRepo.save(newUser);

    await this.emailVerificationPendingRepo.remove(foundRequest); // remove from db

    return {
      message: 'Account verified successfully',
      account: {
        email: savedAccount.email,
        name: savedAccount.firstName + ' ' + savedAccount.lastName,
      },
    };
  }

  async register(registerDto: RegisterDto) {
    const foundAccount = await this.accountsRepo.findOneBy({
      email: registerDto.email,
    });

    if (foundAccount && foundAccount.isVerified) throw new ConflictException('User with this email already exists');

    // handle if the account is not verified
    if (foundAccount && !foundAccount.isVerified) {
      Object.assign(foundAccount, {
        ...registerDto,
      })

      await this.accountsRepo.save(foundAccount);

      return await this.authHelper.sendConfirmationEmail(foundAccount);
    }

    // create new account
    const newAccount = this.accountsRepo.create(registerDto);
    await this.accountsRepo.save(newAccount);

    return await this.authHelper.sendConfirmationEmail(newAccount);
  }


}
