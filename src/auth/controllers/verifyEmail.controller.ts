// src/auth/verifyEmail.controller.ts
import { Controller, Body, Post, HttpStatus, Res, Req } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { ApiTags, ApiResponse, ApiOperation, ApiOkResponse, ApiBody } from '@nestjs/swagger';
import { UserService } from 'src/user/user.service';
import { MailService } from '../mail.service';
import { VerifyEmailDto } from '../dto/verify-email.dto';

@ApiTags('Auth')
@Controller('/auth')
export class VerifyEmailController {
    constructor(
        private authService: AuthService,
        private userService: UserService,
        private mailService: MailService,
    ) { }

    // SEND EMAIL TO VERIFY THE ACCOUNT
    @Post('/verify-email')
    @ApiOperation({ summary: 'Send verification code to the email for account verification' })
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
    @ApiBody({
        description: '"<b>redirectUrl</b>": Determines the url to which the user will be redirected after clicking on the verify link in the email <br><br>',
        type: VerifyEmailDto
    })
    async sendVerifyEmail(@Body() verifyEmailDto: VerifyEmailDto,  @Res() res, @Req() req, tokenType: string): Promise<any> {
        const user = await this.userService.findOneByEmail(verifyEmailDto.email);

        if (!tokenType){
            tokenType = "isActivationCode"
        }

        // Generate a reset token using JWT
        const resetToken = this.authService.generateResetToken(user, tokenType, verifyEmailDto.redirectUrl);
        const apiUrl = `${req.protocol}://${req.get('host')}`;
        
        // Construct the reset link
        const resetLink = `${apiUrl}/auth/activate-account/${resetToken}`;
    
        // Send the email with the reset link
        const emailContent = `To activate your account, please click the following link: \n\n${resetLink}`;
        await this.mailService.sendMail( user.email, process.env.APP_NAME + " | VERIFY ACCOUNT", emailContent );

        return res.status(HttpStatus.OK).send({
            message: ['Email sended successfully'],
            error: "",
            statusCode: 200
        });
    }
}