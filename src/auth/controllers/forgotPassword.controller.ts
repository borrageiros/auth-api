// src/auth/forgotPassword.controller.ts
import { Controller, Body, Post, HttpStatus, Res, Req, NotFoundException } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { ApiTags, ApiResponse, ApiOperation, ApiOkResponse } from '@nestjs/swagger';
import { UserService } from 'src/user/user.service';
import { MailService } from '../mail.service';
import { ForgotPasswordDto } from '../dto/forgot-password.dto';

@ApiTags('Auth')
@Controller('/auth')
export class ForgotPasswordController {
    constructor(
        private authService: AuthService,
        private userService: UserService,
        private mailService: MailService,
    ) { }
 
    // FORGOT PASSWORD | RECOVERY CODE REQUEST
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
    async forgotPassword(@Res() res, @Body() forgotPasswordDto: ForgotPasswordDto, @Req() req) {
        const email = forgotPasswordDto.email;
    
        // Check if email exists
        const user = await this.userService.findOneByEmail(email);
        if (!user) {
            throw new NotFoundException(['User not found with provided email']);
        }
    
        // Generate a reset token using JWT
        const resetToken = this.authService.generateResetToken(user, "isActivationCode", "");
    
        // Send the email with the reset link
        const emailContent = `To reset your password, please copy the following code: \n\n${resetToken}`;
        await this.mailService.sendMail(email, process.env.APP_NAME + " | RECOVERY PASSWORD", emailContent);

        return res.status(HttpStatus.OK).send({
            message: ['Email sended successfully'],
            error: "",
            statusCode: 200
        });
    }  
}