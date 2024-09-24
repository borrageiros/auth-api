// src/user/controllers/changePassword.controller.ts
import { Body, Controller, UseGuards, Request, BadRequestException, UnauthorizedException, Res, HttpStatus, ConflictException, Patch } from '@nestjs/common';
import { UserService } from '../../user.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ChangePasswordDto } from '../../dto/change-password.dto';
import { AuthService } from 'src/auth/auth.service';
import { ActiveUserGuard } from '../../active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/users')
export class ChangePasswordController {
    constructor(
        private userService: UserService,
        private authService: AuthService,
    ) { }

    // CHANGE PASSWORD
    @Patch('/change-password')
    @ApiTags('User')
    @ApiOperation({ summary: 'Change password' })
    @ApiOkResponse({
        description: 'Password changed successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Password changed successfully'
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'Not found' })
    @ApiResponse({ status: 409, description: 'The passwords do not match' })
    async changePassword(@Request() req, @Body() changePasswordDto: ChangePasswordDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);

        //Check password
        const user = await this.authService.validateUser(connectedUser.username, changePasswordDto.password, res)
        if (!user) {
            throw new UnauthorizedException(['Incorrect password']);
        }

        // Confirm passwords
        if (changePasswordDto.newPassword !== changePasswordDto.confirmPassword) {
            throw new BadRequestException(['The passwords do not match'])
        }

        // Check if the new password is different from the old one
        if (changePasswordDto.password === changePasswordDto.newPassword) {
            throw new ConflictException(['The password cannot be the same as the previous one']);
        }

        await this.userService.changePassword( connectedUser.id, changePasswordDto.newPassword );
        return res.status(HttpStatus.OK).send({
            message:  ['Password changed successfully'],
            error: "",
            statusCode: 200
        });
    }
        
}
