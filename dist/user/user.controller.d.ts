import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './user.entity';
export declare class UserController {
    private userService;
    constructor(userService: UserService);
    register(createUserDto: CreateUserDto): Promise<User>;
}
