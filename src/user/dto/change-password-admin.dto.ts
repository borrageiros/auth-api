// src/user/dto/change-password-admin.dto.ts
import { IsNotEmpty, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangePasswordAdminDto {
  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(50)
  userOrIdToChange: string;
  
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