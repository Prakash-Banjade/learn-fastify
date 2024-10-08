import { Inject, Injectable, Scope, UnauthorizedException } from "@nestjs/common";
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
import { EmailVerificationDto } from "../dto/email-verification.dto";
import * as bcrypt from 'bcrypt';

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
    private readonly accountsRepo = this.datasource.getRepository<Account>(Account);

    /**
     * Verification token generation:
     * 
     * 1. Generate a jwt token with email as payload
     * 2. Encrypt the jwt token
     * 3. Hash the encrypted token
     * 4. Save the hashed token in db
     * 5. Send the encrypted token to the user's email
     */
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

    public encrypt(data: string) {
        const cipher = crypto.createCipheriv(this.algorithm, this.aes_key, this.aes_iv); // Create cipher with algorithm, key, and IV
        let encrypted = cipher.update(data, 'utf8', 'hex'); // Encrypt text
        encrypted += cipher.final('hex'); // Finalize encryption
        return { encryptedData: encrypted, iv: this.aes_iv.toString('hex'), key: this.aes_key.toString('hex') };
    }

    public decrypt(cipherText: string) {
        const decipher = crypto.createDecipheriv(this.algorithm, this.aes_key, this.aes_iv); // Create decipher
        let decrypted = decipher.update(cipherText, 'hex', 'utf8'); // Decrypt text
        decrypted += decipher.final('utf8'); // Finalize decryption
        return decrypted;
    }

    async verifyEmail(emailVerificationDto: EmailVerificationDto) {
        const { otp, verificationToken } = emailVerificationDto;

        const decryptedToken = this.decrypt(verificationToken);

        // verify jwt token
        const payload = await this.jwtService.verifyAsync(decryptedToken, {
            secret: this.configService.get('ACCESS_TOKEN_VERIFICATION_SECRET'),
        });

        console.log(payload)
    }

    async validateAccount(email: string, password: string): Promise<Account> {
        const foundAccount = await this.accountsRepo.findOneBy({ email });

        if (!foundAccount) throw new UnauthorizedException('Invalid email. Proceed to sign up.');

        const isPasswordValid = await bcrypt.compare(
            password,
            foundAccount.password,
        );

        if (!isPasswordValid) throw new UnauthorizedException('Invalid password')

        return foundAccount;
    }


}