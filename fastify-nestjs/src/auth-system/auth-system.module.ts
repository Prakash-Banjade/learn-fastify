import { Module } from '@nestjs/common';
import { UsersModule } from './users/users.module';
import { AccountsModule } from './accounts/accounts.module';
import { CaslModule } from './casl/casl.module';

@Module({
    imports: [
        UsersModule,
        AccountsModule,
        CaslModule,
    ]
})
export class AuthSystemModule {}
