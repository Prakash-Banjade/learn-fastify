import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { IS_PUBLIC_KEY } from "../decorators/setPublicRoute.decorator";
import { FastifyRequest } from "fastify";

@Injectable()
export class AuthGuard implements CanActivate {
    constructor(private jwtService: JwtService, private reflector: Reflector) { }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (isPublic) return true;

        const request = context.switchToHttp().getRequest();
        const access_token = this.extractTokenFromHeader(request);
        const refresh_token = request.cookies?.refresh_token;
        if (!access_token) throw new UnauthorizedException();
        try {
            await this.jwtService.verifyAsync(refresh_token, {
                secret: process.env.REFRESH_TOKEN_SECRET,
            })

            const payload = await this.jwtService.verifyAsync(access_token, {
                secret: process.env.ACCESS_TOKEN_SECRET,
            });
            request['user'] = payload;
        } catch {
            throw new UnauthorizedException();
        }
        return true;
    }

    private extractTokenFromHeader(request: FastifyRequest): string | undefined {
        const [type, token] = request.headers.authorization?.split(' ') ?? [];
        return type === 'Bearer' ? token : undefined;
    }
}
