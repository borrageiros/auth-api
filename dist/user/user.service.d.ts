import { Repository } from 'typeorm';
import { User } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';
export declare class UserService {
    private userRepository;
    constructor(userRepository: Repository<User>);
    findUserById(id: number): Promise<User>;
    findOneByUsername(username: string): Promise<User>;
    findOneByEmail(email: string): Promise<User>;
    changeUsernameConnectedUser(connectedUserId: number, newUsername: string): Promise<User>;
    create(createUserDto: CreateUserDto): Promise<any>;
}
