import { PassportStrategy } from "@nestjs/passport";
import { Strategy } from "passport-local";
import { AuthService } from "../auth.service";
import { Injectable } from "@nestjs/common";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(private readonly authService: AuthService) {
        console.log('LocalStrategy Initialized'); // Add a log to ensure it's loaded

        super({
            usernameField: 'email',
        })
    }

    async validate(email: string, password: string) {
        return await this.authService.validateAccount(email, password);
    }


}