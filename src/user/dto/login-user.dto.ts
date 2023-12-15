// src/user/dto/login-user.dto.ts
import { IsNotEmpty, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginUserDto {
  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(50)
  usernameOrEmail: string;

  @ApiProperty()
  @IsNotEmpty()
  @MinLength(4)
  password: string;
}