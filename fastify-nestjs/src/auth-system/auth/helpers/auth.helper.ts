import { Inject, Injectable, Scope } from "@nestjs/common";
import { Account } from "src/auth-system/accounts/entities/account.entity";
import { MailService } from "src/mail/mail.service";
import { generateOtp } from "src/utils/generateOPT";
import * as crypto from 'crypto'
import { BaseRepository } from "src/common/repository/base-repository";
import { DataSource } from "typeorm";
import { FastifyRequest } from "fastify";
import { REQUEST } from "@nestjs/core";
import { EmailVerificationPending } from "../entities/email-verification-pending.entity";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable({ scope: Scope.REQUEST })
export class AuthHelper extends BaseRepository {
    constructor(
        private readonly datasource: DataSource,
        @Inject(REQUEST) req: FastifyRequest,
        private readonly mailService: MailService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
    ) {
        super(datasource, req);
    }

    private readonly algorithm = 'aes-256-cbc';
    private readonly aes_key = Buffer.from(this.configService.get<string>('AES_KEY'), 'hex'); // 32 bytes key
    private readonly aes_iv = Buffer.from(this.configService.get<string>('AES_IV'), 'hex'); // 16 bytes iv 

    private readonly emailVerificationPendingRepo = this.datasource.getRepository<EmailVerificationPending>(EmailVerificationPending)

    async sendConfirmationEmail(account: Account) {
        // check for existing verification pending, if yes, remove
        const existingVerificationRequest = await this.emailVerificationPendingRepo.findOneBy({ email: account.email });
        if (existingVerificationRequest) await this.emailVerificationPendingRepo.remove(existingVerificationRequest);

        const otp = generateOtp();
        const verificationToken = await this.jwtService.signAsync(
            { email: account.email },
            {
                secret: this.configService.get('ACCESS_TOKEN_VERIFICATION_SECRET'),
                expiresIn: '30m',
            }
        );

        const encryptedVerificationToken = this.encrypt(verificationToken);

        const hashedVerificationToken = crypto
            .createHash('sha256')
            .update(encryptedVerificationToken.encryptedData)
            .digest('hex');

        // save the request to db
        const emailVerificationPending = this.emailVerificationPendingRepo.create({
            email: account.email,
            otp: String(otp), // opt is saved as hash in db, logic is implemented in email-verification-pending.entity.ts
            hashedVerificationToken,
        });
        await this.emailVerificationPendingRepo.save(emailVerificationPending);

        await this.mailService.sendConfirmationEmail(account, encryptedVerificationToken.encryptedData, otp);

        return {
            message: "An OTP has been sent to your email. Please use the OTP to verify your account."
        }
    }

    encrypt(data: string) {
        const cipher = crypto.createCipheriv(this.algorithm, this.aes_key, this.aes_iv); // Create cipher with algorithm, key, and IV
        let encrypted = cipher.update(data, 'utf8', 'hex'); // Encrypt text
        encrypted += cipher.final('hex'); // Finalize encryption
        return { encryptedData: encrypted, iv: this.aes_iv.toString('hex'), key: this.aes_key.toString('hex') };
    }
}