// src/user/dto/change-username-admin.dto.ts
import { IsNotEmpty, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangeUsernameAdminDto {
  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(50)
  userOrIdToChange: string;
  
  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(50)
  newUsername: string;
}