import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { FastifyRequest } from "fastify";

@Injectable()
export class RefreshTokenGuard implements CanActivate {
    constructor(private jwtService: JwtService, private reflector: Reflector) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const request = context.switchToHttp().getRequest();
        const refresh_token = this.extractTokenFromHeader(request);

        if (!refresh_token) throw new UnauthorizedException();
        try {
            await this.jwtService.verifyAsync(refresh_token, {
                secret: process.env.REFRESH_TOKEN_SECRET,
            })

            request.cookies.refresh_token = refresh_token;
        } catch {
            throw new UnauthorizedException();
        }
        return true;
    }

    private extractTokenFromHeader(request: FastifyRequest): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Refresh' ? token : undefined;
    }
}
