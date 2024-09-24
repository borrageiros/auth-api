// src/user/dto/change-password.dto.ts
import { IsNotEmpty, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangePasswordDto {
  @ApiProperty()
  @IsNotEmpty()
  @MinLength(4)
  password: string;

  @ApiProperty()
  @IsNotEmpty()
  @MinLength(4)
  @MaxLength(50)
  newPassword: string;

  @ApiProperty()
  @IsNotEmpty()
  @MinLength(4)
  @MaxLength(50)
  confirmPassword: string;
}