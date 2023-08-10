import { User } from '../user.entity';
import { Exclude } from 'class-transformer';

export class PublicUserInfo extends User {
    @Exclude()
    id: number;

    @Exclude()
    password: string;

    @Exclude()
    updatedAt: Date;
}
