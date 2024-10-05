import {
  Inject,
  Injectable,
  Scope,
} from '@nestjs/common';
import { DataSource } from 'typeorm';
import { PasswordChangeRequest } from './entities/password-change-request.entity';
import { MailService } from 'src/mail/mail.service';
import { EmailVerificationPending } from './entities/email-verification-pending.entity';
import { BaseRepository } from 'src/common/repository/base-repository';
import { REQUEST } from '@nestjs/core';
import { FastifyRequest } from 'fastify';
import { Account } from '../accounts/entities/account.entity';
import { User } from '../users/entities/user.entity';

@Injectable({ scope: Scope.REQUEST })
export class AuthService extends BaseRepository {
  constructor(
    private readonly datasource: DataSource,
    @Inject(REQUEST) req: FastifyRequest,
    private readonly mailService: MailService,
  ) { super(datasource, req) }

  private readonly accountsRepo = this.datasource.getRepository<Account>(Account)
  private readonly usersRepo = this.datasource.getRepository<User>(User)
  private readonly emailVerificationPendingRepo = this.datasource.getRepository<EmailVerificationPending>(EmailVerificationPending)
  private readonly passwordChangeRequestRepo = this.datasource.getRepository<PasswordChangeRequest>(PasswordChangeRequest)


}
