import { JwtService } from '@nestjs/jwt';
import { UserService } from '../user/user.service';
import { User } from 'src/user/user.entity';
export declare class AuthService {
    private userService;
    private jwtService;
    constructor(userService: UserService, jwtService: JwtService);
    generateResetToken(user: User): string;
    validateUser(usernameOrEmail: string, password: string, res: any): Promise<any>;
    login(usernameOrEmail: string, password: string, res: any): Promise<{
        access_token: string;
    }>;
}
