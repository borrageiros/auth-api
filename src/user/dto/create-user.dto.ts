// src/user/dto/create-user.dto.ts
import { IsEmail, IsNotEmpty, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateUserDto {
  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(50)
  username: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsEmail()
  @MaxLength(100)
  email: string;

  @ApiProperty()
  @IsNotEmpty()
  @MinLength(4)
  password: string;
}