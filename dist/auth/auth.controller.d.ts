import { AuthService } from './auth.service';
import { UserService } from 'src/user/user.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { LoginUserDto } from 'src/user/dto/login-user.dto';
export declare class AuthController {
    private authService;
    private userService;
    constructor(authService: AuthService, userService: UserService);
    register(createUserDto: CreateUserDto): Promise<any>;
    login(loginUserDto: LoginUserDto, res: any): Promise<any>;
}
