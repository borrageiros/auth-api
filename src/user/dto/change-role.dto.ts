// src/user/dto/change-role.dto.ts
import { IsNotEmpty, MaxLength, IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { UserRole } from '../user.entity';

const validRoles = Object.values(UserRole).join(', ');

export class ChangeRoleDto {
  @ApiProperty()
  @IsNotEmpty()
  @MaxLength(50)
  userOrIdToChange: string;

  @ApiProperty()
  @IsNotEmpty()
  @IsEnum(UserRole, { message: `newRole must be (${validRoles})` })
  newRole: UserRole;
}