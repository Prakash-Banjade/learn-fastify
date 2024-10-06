import { Body, Controller, HttpCode, HttpStatus, Post, Request, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiTags } from '@nestjs/swagger';
import { LocalAuthGuard } from 'src/common/guards/local-auth.guard';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { AuthUser } from 'src/common/types/global.type';
import { FastifyReply, FastifyRequest } from 'fastify';
import { RegisterDto } from './dto/register.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('login')
    @UseGuards(LocalAuthGuard)
    @HttpCode(HttpStatus.OK)
    async login(
        @Request() req: FastifyRequest & { user: AuthUser },
        // @Res({ passthrough: true }) res: FastifyReply
    ) {
        console.log(req.user);
    }

    @Post('register')
    @HttpCode(HttpStatus.CREATED)
    async register(@Body() registerDto: RegisterDto) {
        return this.authService.register(registerDto);
    }

}
