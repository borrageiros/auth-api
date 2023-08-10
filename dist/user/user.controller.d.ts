import { UserService } from './user.service';
import { ChangeUsernameDto } from './dto/change-username.dto';
import { AuthService } from 'src/auth/auth.service';
import { ChangeEmailDto } from './dto/change-email.dto';
export declare class UserController {
    private userService;
    private authService;
    constructor(userService: UserService, authService: AuthService);
    getUserByUsername(username: string, res: any): Promise<any>;
    getUserByToken(res: any, req: any): Promise<any>;
    searchUsersByUsername(username: string, res: any): Promise<any>;
    changeUsername(req: any, changeUsernameDto: ChangeUsernameDto, res: any): Promise<any>;
    changeEmail(req: any, changeEmailDto: ChangeEmailDto, res: any): Promise<any>;
}
