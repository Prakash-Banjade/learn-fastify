import { BeforeInsert, BeforeUpdate, Column, Entity, JoinColumn, OneToMany, OneToOne } from "typeorm";
import * as bcrypt from 'bcrypt';
import { BadRequestException } from "@nestjs/common";
import { BaseEntity } from "src/common/entities/base.entity";
import { Role } from "src/common/types/global.type";
import { User } from "src/auth-system/users/entities/user.entity";
import { Image } from "src/file-management/images/entities/image.entity";

@Entity()
export class Account extends BaseEntity {
    @Column({ type: 'varchar' })
    firstName!: string;

    @Column({ type: 'varchar', default: '' })
    lastName?: string;

    @Column({ type: 'varchar' })
    email!: string;

    @Column({ type: 'varchar', nullable: true })
    password?: string;

    @Column({ type: 'enum', enum: Role, default: Role.USER })
    role: Role;

    @Column({ type: 'simple-array', nullable: true })
    refresh_token: string[];

    @Column({ type: 'boolean', default: false })
    isVerified: boolean = false;

    @OneToOne(() => User, user => user.account, { onDelete: 'CASCADE', nullable: true })
    @JoinColumn()
    user: User

    @OneToMany(() => Image, image => image.uploadedBy)
    images: Image[]
    
    @BeforeInsert()
    hashPassword() {
        if (!this.password) throw new BadRequestException('Password required');

        this.password = bcrypt.hashSync(this.password, 10);
    }

    @BeforeInsert()
    @BeforeUpdate()
    validateEmail() {
        if (!this.email) throw new BadRequestException('Email required');

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(this.email)) throw new BadRequestException('Invalid email');
    }

}
