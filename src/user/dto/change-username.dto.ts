// src/user/dto/change-username.dto.ts
import { IsNotEmpty, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class ChangeUsernameDto {
  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(50)
  newUsername: string;

  @ApiProperty()
  @IsNotEmpty()
  @MinLength(4)
  password: string;
}