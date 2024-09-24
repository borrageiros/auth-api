// src/user/dto/change-email-admin.dto.ts
import { IsNotEmpty, MaxLength, IsOptional, IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangeEmailAdminDto {
  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(50)
  userOrIdToChange: string;
  
  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(100)
  newEmail: string;

  @ApiProperty()
  @IsOptional()
  deactivateUser: boolean;
}