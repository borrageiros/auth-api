// src/auth/dto/reset-password.dto.ts
import { IsNotEmpty, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ResetPasswordDto {
    @ApiProperty()
    @IsNotEmpty()
    recoveryCode: string;

    @ApiProperty()
    @IsNotEmpty()
    @MinLength(4)
    newPassword: string;

    @ApiProperty()
    @IsNotEmpty()
    @MinLength(4)
    confirmPassword: string;
}