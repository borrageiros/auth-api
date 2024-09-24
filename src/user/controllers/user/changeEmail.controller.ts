// src/user/controllers/changeEmail.controller.ts
import { Body, Controller, UseGuards, Request, UnauthorizedException, Res, HttpStatus, ConflictException, Patch } from '@nestjs/common';
import { UserService } from '../../user.service';
import { User } from '../../user.entity';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse, ApiBody } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from 'src/auth/auth.service';
import { ChangeEmailDto } from '../../dto/change-email.dto';
import { ActiveUserGuard } from '../../active-user-guard';
import { MailService } from 'src/auth/mail.service';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@UseGuards(AuthGuard('jwt')) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/users')
export class ChangeEmailController {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        private userService: UserService,
        private authService: AuthService,
        private mailService: MailService,
    ) { }

    // CHANGE EMAIL
    @Patch('/change-email')
    @ApiTags('User')
    @ApiOperation({ summary: 'Change email' })
    @ApiOkResponse({
        description: 'Email changed successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Email changed successfully'
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'Not found' })
    @ApiResponse({ status: 409, description: 'Conflict' })
    @ApiBody({
        description: '<b><h1>IMPORTANT</h1> <h3>THIS WILL DEACTIVATE THE ACCOUNT AND SEND A NEW VERIFICATION CODE TO THE EMAIL</h3></b> <br>\
        "<b>redirectUrl</b>": Determines the url to which the user will be redirected after clicking on the verify link in the email <br><br>',
        type: ChangeEmailDto
    })
    async changeEmail(@Request() req, @Body() changeEmailDto: ChangeEmailDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);

        //Check password
        let user = await this.authService.validateUser(connectedUser.username, changeEmailDto.password, res)
        if (!user) {
            throw new UnauthorizedException(['Incorrect password']);
        }

        // Check if email exist and change it
        try {
            user = await this.userService.changeEmail( connectedUser.id, changeEmailDto.newEmail );
        } catch (error) {
            if (error.sqlMessage.includes(changeEmailDto.newEmail)) {
                throw new ConflictException(['Email already in use']);
            }
        }

        // Send email verification
        const resetToken = this.authService.generateResetToken( user, "isActivationCode", changeEmailDto.redirectUrl );
        const apiUrl = `${req.protocol}://${req.get('host')}`;
        const resetLink = `${apiUrl}/auth/activate-account/${resetToken}`;
        const emailContent = `To activate your account, please click the following link: \n\n${resetLink}`;
        await this.mailService.sendMail( changeEmailDto.newEmail, process.env.APP_NAME + " | VERIFY ACCOUNT", emailContent );

        // Desactivate the user
        user.actived = false;
        await this.userRepository.save(user);

        return res.status(HttpStatus.OK).send({
            message:  ['Email changed successfully'],
            error: "",
            statusCode: 200
        });
    }
        
}