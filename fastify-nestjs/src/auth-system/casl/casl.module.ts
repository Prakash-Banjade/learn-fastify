import { Module } from '@nestjs/common';
import { CaslAbilityFactory } from './casl-ability.factory/casl-ability.factory';
import { APP_GUARD } from '@nestjs/core';
import { AbilitiesGuard } from 'src/common/guards/abilities.guard';

@Module({
    providers: [
        CaslAbilityFactory,
        {
            provide: APP_GUARD,
            useClass: AbilitiesGuard, // global ability guard
        },
    ],
    exports: [CaslAbilityFactory],
})
export class CaslModule { }
