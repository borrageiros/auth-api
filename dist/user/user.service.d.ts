import { Repository } from 'typeorm';
import { User } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';
export declare class UserService {
    private userRepository;
    constructor(userRepository: Repository<User>);
    findOneByUsername(username: string): Promise<User>;
    findOneByEmail(email: string): Promise<User>;
    create(createUserDto: CreateUserDto): Promise<User>;
}
