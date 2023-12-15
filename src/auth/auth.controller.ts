// src/auth/auth.controller.ts
import { Controller, Body, Post, HttpStatus, Res, Patch, Query, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiTags, ApiResponse, ApiOperation, ApiOkResponse, ApiCreatedResponse, ApiQuery, ApiParam, ApiProperty } from '@nestjs/swagger';
import { UserService } from 'src/user/user.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { LoginUserDto } from 'src/user/dto/login-user.dto';
import { MailService } from './mail.service';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/user.entity';
import { Repository } from 'typeorm';
import { JwtStrategy } from './jwt.strategy';
import * as bcrypt from 'bcrypt';
import { ForgotPasswordDto } from './dto/forgot-password.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { ActiveUserGuard } from 'src/user/active-user-guard';

@ApiTags('Auth')
@Controller('/auth')
export class AuthController {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        private authService: AuthService,
        private userService: UserService,
        private mailService: MailService,
        private jwtStrategy: JwtStrategy
    ) { }
 
    //////////////////////// REGISTER
    @Post('/register')
    @ApiOperation({ summary: 'Register a user' })
    @ApiCreatedResponse({
        description: 'User created',
        schema: {
            type: 'object',
            properties: {
                access_token: {
                    type: 'string',
                    example: 'string'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 409, description: 'Username or email conflict' })
    async register(@Body() createUserDto: CreateUserDto, @Res() res): Promise<any> {
        const user = await this.userService.create(createUserDto);
        return this.sendVerifyEmail(user, res, "isActivationCode")
    }
    ////////////////////////



    //////////////////////// LOG-IN
    @UseGuards( ActiveUserGuard )
    @Post('/login')
    @ApiOperation({ summary: 'Log-in' })
    @ApiOkResponse({
        description: 'Log-in successfully',
        schema: {
            type: 'object',
            properties: {
                access_token: {
                    type: 'string',
                    example: 'string'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 404, description: 'No user found with username or email' })
    async login(@Body() loginUserDto: LoginUserDto, @Res() res) {
        const result = await this.authService.login(loginUserDto.usernameOrEmail, loginUserDto.password, res);
        return res.status(HttpStatus.OK).send(result);
    }
    ////////////////////////



    //////////////////////// VERIFY EMAIL
    @Post('/activate-account')
    @ApiOperation({ summary: 'Verify email to activate the account' })
    @ApiOkResponse({
        description: 'Account verified',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Account verified'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 404, description: 'User not found' })
    @ApiQuery({ name: "activateCode", description: "The code to activate the account", type: String, required: false})
    async verifyEmail(@Query() body, @Res() res): Promise<any> {
        const recoveryCode = body.activateCode;

        // Verify jwtToken
        let decoded;
        try {
            decoded = await this.jwtStrategy.decode(recoveryCode);
        } catch (error) {
            return res.status(HttpStatus.BAD_REQUEST).send({ message: ['Invalid activation code'] });
        }

        // Check token type
        if (decoded.isActivationCode === false) {
            return res.status(HttpStatus.BAD_REQUEST).send({ message: ['This code is not for activate the account'] });
        }

        // Check if token is expired
        if (decoded.exp < Math.floor(Date.now() / 1000)) {
            return res.status(HttpStatus.BAD_REQUEST).send({ message: ['This code is expired'] });
        }

        const user = await this.userService.findOneByUsername(decoded.username);
        if (!user) {
            return res.status(HttpStatus.NOT_FOUND).send({ message: ['Invalid activate code'] });
        }

        // Activate the user
        user.actived = true;
        await this.userRepository.save(user);

        return res.status(HttpStatus.OK).send({ message: ['Account verified'] });
    }
    ////////////////////////



    //////////////////////// SEND EMAIL TO VERIFY THE ACCOUNT
    @Post('/verify-email')
    @ApiOperation({ summary: 'Send code account verification to the email' })
    @ApiOkResponse({
        description: 'Email sended successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Email sended successfully'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 404, description: 'User not found' })
    @ApiQuery({ name: "email", description: "Email of the account to verify", type: String, required: false})
    async sendVerifyEmail(@Query() body, @Res() res, tokenType: string): Promise<any> {
        const user = await this.userService.findOneByEmail(body.email);

        if (!tokenType){
            tokenType = "isActivationCode"
        }

        // Generate a reset token using JWT
        const resetToken = this.authService.generateResetToken(user, tokenType);
        
        // Construct the reset link
        const resetLink = `${process.env.FRONT_END_URL}/activate-account?token=${resetToken}`;
    
        // Send the email with the reset link
        const emailContent = `To activate your account, please click the following link: \n ${resetLink}`;
        await this.mailService.sendMail( user.email, process.env.APP_NAME + " | VERIFY ACCOUNT", emailContent );
    
        return res.status(HttpStatus.OK).send({ message: ['Email sended successfully'] });
    }
    ////////////////////////



    //////////////////////// FORGOT PASSWORD | RECOVERY CODE REQUEST
    @Post('/forgot-password')
    @ApiOperation({ summary: 'Send recovery code request to a email' })
    @ApiOkResponse({
        description: 'Email sended successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Email sended successfully'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 404, description: 'No user found with email {email}' })
    async forgotPassword(@Res() res, @Body() forgotPasswordDto: ForgotPasswordDto) {
        const email = forgotPasswordDto.email;
    
        // Check if email exists
        const user = await this.userService.findOneByEmail(email);
        if (!user) {
            return res.status(HttpStatus.NOT_FOUND).send({ message: ['User not found with provided email'] });
        }
    
        // Generate a reset token using JWT
        const resetToken = this.authService.generateResetToken(user, "isPasswordReset");
    
        // Construct the reset link
        const resetLink = `${process.env.FRONT_END_URL}/reset-password?token=${resetToken}`;
    
        // Send the email with the reset link
        const emailContent = `To reset your password, please click the following link: \n ${resetLink}`;
        await this.mailService.sendMail(email, process.env.APP_NAME + " | RECOVERY PASSWORD", emailContent);
    
        return res.status(HttpStatus.OK).send({ message: ['Email sended successfully'] });
    }      
    ////////////////////////


    //////////////////////// RESET PASSWORD | SET NEW PASSWORD
    @Post('/reset-password')
    @ApiOperation({ summary: 'Set new password with recovery code from email' })
    @ApiOkResponse({
        description: 'Password reset successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Password reset successfully'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 404, description: 'Invalid recovery code' })
    async resetPassword(@Res() res, @Body() resetPasswordDto: ResetPasswordDto) {
        const { recoveryCode, newPassword, confirmPassword } = resetPasswordDto;

        if (newPassword !== confirmPassword) {
            return res.status(HttpStatus.BAD_REQUEST).send({ message: ['New password and confirm password do not match'] });
        }

        // Verify jwtToken
        let decoded;
        try {
            decoded = await this.jwtStrategy.decode(recoveryCode);
        } catch (error) {
            return res.status(HttpStatus.BAD_REQUEST).send({ message: ['Invalid recovery code'] });
        }

        // Check token type
        if (decoded.isPasswordReset === false) {
            return res.status(HttpStatus.BAD_REQUEST).send({ message: ['This code is not for password resetting'] });
        }

        // Check if token is expired
        if (decoded.exp < Math.floor(Date.now() / 1000)) {
            return res.status(HttpStatus.BAD_REQUEST).send({ message: ['This code is expired'] });
        }

        const user = await this.userService.findOneByUsername(decoded.username);
        if (!user) {
            return res.status(HttpStatus.NOT_FOUND).send({ message: ['Invalid recovery code'] });
        }

        // Update password
        const salt = await bcrypt.genSalt();
        user.password = await bcrypt.hash(newPassword, salt);
        await this.userRepository.save(user);

        return res.status(HttpStatus.OK).send({ message: ['Password reset successfully'] });
    }
    ////////////////////////
}
