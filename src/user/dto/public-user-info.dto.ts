// src/user/dto/public-user-info.dto.ts
import { User } from '../user.entity';
import { Exclude } from 'class-transformer';

export class PublicUserInfo extends User {
    @Exclude()
    password: string;

    @Exclude()
    updatedAt: Date;
}
