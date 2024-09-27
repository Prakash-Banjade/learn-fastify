import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { AccountsModule } from './accounts/accounts.module';
import { CaslModule } from './casl/casl.module';
import { APP_GUARD } from '@nestjs/core';
import { AbilitiesGuard } from 'src/common/guards/abilities.guard';
import { AuthGuard } from 'src/common/guards/auth.guard';
import { AuthModule } from './auth/auth.module';

@Module({
    imports: [
        UsersModule,
        AccountsModule,
        CaslModule,
        AuthModule,
    ],
    providers: [
        {
            provide: APP_GUARD,
            useClass: AuthGuard, // global auth guard
        },
        {
            provide: APP_GUARD,
            useClass: AbilitiesGuard, // global ability guard
        },
    ]
})
export class AuthSystemModule { }
