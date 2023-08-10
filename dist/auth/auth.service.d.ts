import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
export declare class AuthService {
    private userService;
    private jwtService;
    constructor(userService: UserService, jwtService: JwtService);
    validateUser(usernameOrEmail: string, password: string): Promise<any>;
    login(usernameOrEmail: string, password: string): Promise<{
        access_token: string;
    }>;
}
