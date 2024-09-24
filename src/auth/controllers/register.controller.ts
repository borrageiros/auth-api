// src/auth/register.controller.ts
import { Controller, Body, Post, HttpStatus, Res, Req } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { ApiTags, ApiResponse, ApiOperation, ApiCreatedResponse, ApiBody, ApiParam } from '@nestjs/swagger';
import { UserService } from 'src/user/user.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { MailService } from '../mail.service';


@ApiTags('Auth')
@Controller('/auth')
export class RegisterController {
    constructor(
        private authService: AuthService,
        private userService: UserService,
        private mailService: MailService,
    ) { }
 
    // REGISTER
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
    @ApiBody({
        description: '"<b>redirectUrl</b>": Determines the url to which the user will be redirected after clicking on the verify link in the email <br><br>',
        type: CreateUserDto
    })
    async register(@Body() createUserDto: CreateUserDto, @Res() res, @Req() req ): Promise<any> {
        const user = await this.userService.create(createUserDto);

        // Generate a reset token using JWT
        const resetToken = this.authService.generateResetToken(user, "isActivationCode", createUserDto.redirectUrl);
        const apiUrl = `${req.protocol}://${req.get('host')}`;

        // Construct the reset link
        const resetLink = `${apiUrl}/auth/activate-account/${resetToken}`;

        // Send the email with the activation link
        const emailContent = `To activate your account, please click the following link: \n\n${resetLink}`;
        await this.mailService.sendMail( user.email, process.env.APP_NAME + " | VERIFY ACCOUNT", emailContent );

        return res.status(HttpStatus.OK).send({
            message: ['User created successfully, check email to verify the account'],
            error: "",
            statusCode: 200
        });
    }
}