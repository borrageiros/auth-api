import { AuthService } from './auth.service';
import { UserService } from 'src/user/user.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { LoginUserDto } from 'src/user/dto/login-user.dto';
import { MailService } from './mail.service';
import { User } from 'src/user/user.entity';
import { Repository } from 'typeorm';
import { JwtStrategy } from './jwt.strategy';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
export declare class AuthController {
    private userRepository;
    private authService;
    private userService;
    private mailService;
    private jwtStrategy;
    constructor(userRepository: Repository<User>, authService: AuthService, userService: UserService, mailService: MailService, jwtStrategy: JwtStrategy);
    register(createUserDto: CreateUserDto, res: any): Promise<any>;
    login(loginUserDto: LoginUserDto, res: any): Promise<any>;
    verifyEmail(body: any, res: any): Promise<any>;
    sendVerifyEmail(user: User, res: any): Promise<any>;
    forgotPassword(res: any, forgotPasswordDto: ForgotPasswordDto): Promise<any>;
    resetPassword(res: any, resetPasswordDto: ResetPasswordDto): Promise<any>;
}
