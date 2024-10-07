import { TemplateDelegate } from 'handlebars';

interface IEmailAuth {
    user: string;
    pass: string;
}

export interface IEmailConfig {
    host: string;
    port: number;
    secure: boolean;
    auth: IEmailAuth;
}

export const emailConfig: IEmailConfig = {
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT, 10),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASSWORD,
    },
}

export interface ITemplatedData {
    name: string;
    link: string;
}


export interface ITemplates {
    confirmation: TemplateDelegate<ITemplatedData>;
    resetPassword: TemplateDelegate<ITemplatedData>;
}