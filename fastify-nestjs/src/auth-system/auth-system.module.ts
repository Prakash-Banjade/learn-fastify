import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { AccountsModule } from './accounts/accounts.module';
import { CaslModule } from './casl/casl.module';
import { AuthModule } from './auth/auth.module';
import { APP_GUARD } from '@nestjs/core';
import { AbilitiesGuard } from 'src/common/guards/abilities.guard';

@Module({
    imports: [
        UsersModule,
        AccountsModule,
        CaslModule,
        AuthModule,
    ],
    providers: [
        // {
        //     provide: APP_GUARD,
        //     useClass: AbilitiesGuard, // global ability guard
        // },
    ]
})
export class AuthSystemModule { }
