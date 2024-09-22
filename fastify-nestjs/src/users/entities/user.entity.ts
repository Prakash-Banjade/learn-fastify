import { Column, Entity, JoinColumn, OneToOne } from "typeorm";
// import { Image } from "src/images/entities/image.entity";
// import { Account } from "src/accounts/entities/account.entity";
import { Gender } from "src/common/types/global.type";
import { BaseEntity } from "src/common/entities/base.entity";

@Entity()
export class User extends BaseEntity {
    @Column({ type: 'varchar', nullable: true })
    phone: string | null;

    @Column({ type: 'enum', enum: Gender, nullable: true })
    gender: Gender | null;

    @Column({ type: 'timestamp', nullable: true })
    dob: string | null;

    // @OneToOne(() => Image, { nullable: true })
    // @JoinColumn()
    // profileImage: Image | null;

    // @OneToOne(() => Account, account => account.user, { nullable: true })
    // account: Account
}
