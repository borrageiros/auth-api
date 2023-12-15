// src/user/dto/change-email.dto.ts
import { IsEmail, IsNotEmpty, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangeEmailDto {
  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(100)
  newEmail: string;

  @ApiProperty()
  @IsNotEmpty()
  @MinLength(4)
  password: string;
}