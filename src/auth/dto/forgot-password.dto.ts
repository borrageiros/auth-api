// src/auth/dto/forgot-password.dto.ts
import { IsEmail, IsNotEmpty, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ForgotPasswordDto {
    @ApiProperty()
    @IsNotEmpty()
    @IsEmail()
    @MaxLength(100)
    email: string;
}