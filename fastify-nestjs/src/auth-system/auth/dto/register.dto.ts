import { ApiProperty } from "@nestjs/swagger";
import { IsEmail, IsNotEmpty, IsOptional, IsString, IsStrongPassword, Length } from "class-validator";

export class RegisterDto {
    @ApiProperty({ type: 'string', description: 'First name of the user' })
    @IsString()
    @IsNotEmpty()
    @Length(2)
    firstName!: string;

    @ApiProperty({ type: 'string', description: 'Last name of the user' })
    @IsString()
    @Length(2)
    @IsOptional()
    lastName?: string;

    @ApiProperty({ type: 'string', format: 'email', description: 'Valid email' })
    @IsEmail()
    @IsNotEmpty()
    email!: string;

    @ApiProperty({ type: 'string', description: 'Enter a strong password' })
    @IsString()
    @IsStrongPassword()
    password!: string;
}