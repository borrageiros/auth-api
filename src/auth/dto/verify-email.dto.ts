// src/auth/dto/verify-email.dto.ts
import { IsEmail, IsNotEmpty, MaxLength, MinLength, IsUrl } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyEmailDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(100)
  email: string;

  @ApiProperty()
  @IsUrl()
  redirectUrl: string;
}