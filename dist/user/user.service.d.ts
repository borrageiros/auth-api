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
    changeUsernameConnectedUser(connectedUserId: number, newUsername: string): Promise<User>;
    changeEmailConnectedUser(connectedUserId: number, newEmail: string): Promise<User>;
    changeUserRole(userId: number, newRole: UserRole): Promise<User>;
    create(createUserDto: CreateUserDto): Promise<any>;
}
