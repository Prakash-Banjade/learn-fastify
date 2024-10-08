import { CookieSerializeOptions } from '@fastify/csrf-protection';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService as JwtSer } from '@nestjs/jwt';
import { Tokens } from 'src/common/CONSTANTS';
import { AuthUser } from 'src/common/types/global.type';

@Injectable()
export class JwtService {
    constructor(
        private readonly jwtService: JwtSer,
        private readonly configService: ConfigService,
    ) { }

    private readonly ACCESS_TOKEN_SECRET = this.configService.getOrThrow<string>('ACCESS_TOKEN_SECRET');
    private readonly ACCESS_TOKEN_EXPIRATION_MS = +this.configService.getOrThrow<number>('ACCESS_TOKEN_EXPIRATION_MS');
    private readonly REFRESH_TOKEN_SECRET = this.configService.getOrThrow<string>('REFRESH_TOKEN_SECRET');
    private readonly REFRESH_TOKEN_EXPIRATION_MS = +this.configService.getOrThrow<number>('REFRESH_TOKEN_EXPIRATION_MS');

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

    async getAuthTokens(payload: AuthUser) {
        const access_token = await this.createAccessToken(payload);
        const refresh_token = await this.createRefreshToken(payload);

        return { access_token, refresh_token };
    }

    public getCookieOptions(tokenType: Tokens.ACCESS_TOKEN_COOKIE_NAME | Tokens.REFRESH_TOKEN_COOKIE_NAME): CookieSerializeOptions {
        const cookieOptions: CookieSerializeOptions = {
            httpOnly: true,
            signed: true,
            secure: this.configService.getOrThrow('NODE_ENV') === 'production',
            sameSite: this.configService.getOrThrow('NODE_ENV') === 'production' ? 'none' : 'lax',
            maxAge: tokenType === Tokens.ACCESS_TOKEN_COOKIE_NAME ? this.ACCESS_TOKEN_EXPIRATION_MS : 60 * 60 * 24,
        };

        return cookieOptions;
    }
}
