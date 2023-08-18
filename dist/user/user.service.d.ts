import { Repository } from 'typeorm';
import { User, UserRole } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';
export declare class UserService {
    private userRepository;
    constructor(userRepository: Repository<User>);
    findAllUsers(): Promise<User[]>;
    findOneById(id: number): Promise<User>;
    findOneByUsername(username: string): Promise<User>;
    findUsersByUsername(username: string): Promise<any>;
    findOneByEmail(email: string): Promise<User>;
    findUsersByEmail(email: string): Promise<any>;
    changeUsername(userId: number, newUsername: string): Promise<User>;
    changeEmail(userId: number, newEmail: string): Promise<User>;
    changeRole(userId: number, newRole: UserRole): Promise<User>;
    deleteOneById(id: number): Promise<void>;
    create(createUserDto: CreateUserDto): Promise<any>;
}
