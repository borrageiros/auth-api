// src/user/controllers/changePasswordAdmin.controller.ts
import { Body, Controller, UseGuards, Request, Res, HttpStatus, ForbiddenException, Patch, NotFoundException, BadRequestException } from '@nestjs/common';
import { UserService } from '../../user.service';
import { User, UserRole } from '../../user.entity';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse, ApiBody } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ActiveUserGuard } from '../../active-user-guard';
import { ChangePasswordAdminDto } from 'src/user/dto/change-password-admin.dto';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/admin')
export class ChangePasswordAdminController {
    constructor(
        private userService: UserService,
    ) { }

    // CHANGE USER PASSWORD
    // "users" cannot change the password for anyone
    // "admin" can change the password for any basic user
    // "root" (super_admin) can change the password for any user/admin/root (all users)
    @Patch('/change-password')
    @ApiTags('Admin')
    @ApiOperation({ summary: 'Change a user password' })
    @ApiOkResponse({
        description: 'Password updated to {password} for {user}',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Password updated to {password} for {user}'
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 403, description: 'Forbidden' })
    @ApiResponse({ status: 404, description: 'Not found' })
    @ApiBody({
        description: '"<b>users</b>" cannot change the password for anyone <br>\
        "<b>admin</b>" can change the password for any basic user <br>\
        "<b>root</b>" (super_admin) can change the password for any user/admin/root (all users) <br><br>',
        type: ChangePasswordAdminDto
    })
    async changePassword(@Request() req, @Body() changePasswordAdminDto: ChangePasswordAdminDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        
        let userToChange: User;     
    
        try {
            if (!isNaN(Number(changePasswordAdminDto.userOrIdToChange))) {
                userToChange = await this.userService.findOneById(changePasswordAdminDto.userOrIdToChange);
            } else {
                userToChange = await this.userService.findOneByUsername(changePasswordAdminDto.userOrIdToChange);
            }            
        } catch (error) {
            throw new NotFoundException(['User not found']);
        }

        // Confirm passwords
        if (changePasswordAdminDto.newPassword !== changePasswordAdminDto.confirmPassword) {
            throw new BadRequestException(['The passwords do not match'])
        }
    
        switch (connectedUser.role) {
            case UserRole.ROOT:
                userToChange.password = changePasswordAdminDto.newPassword;
                break;
    
            case UserRole.ADMIN:
                if (userToChange.role !== UserRole.ROOT && userToChange.role !== UserRole.ADMIN) {
                    userToChange.password = changePasswordAdminDto.newPassword;
                } else {
                    throw new ForbiddenException(["Admins cannot change the password of a admin/root user"]);
                }
                break;
    
            case UserRole.USER:
                throw new ForbiddenException(['You do not have permission to perform this action']);
        }
    
        await this.userService.changePassword( userToChange.id, changePasswordAdminDto.newPassword );
        return res.status(HttpStatus.OK).send({
            message:  ['Password changed successfully'],
            error: "",
            statusCode: 200
        });
    }
        
}
