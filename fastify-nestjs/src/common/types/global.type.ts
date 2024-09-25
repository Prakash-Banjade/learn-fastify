export interface AuthUser {
    userId: string;
    accountId: string;
    name: string;
    email: string;
    image: string;
    role: Role;
}

export enum Action {
    MANAGE = 'manage',
    CREATE = 'create',
    READ = 'read',
    UPDATE = 'update',
    DELETE = 'delete',
    RESTORE = 'restore',
}

export enum Role {
    ADMIN = 'admin',
    USER = 'user',
}

export enum Gender {
    MALE = 'male',
    FEMALE = 'female',
    OTHER = 'other',
}