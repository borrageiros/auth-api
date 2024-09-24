// src/user/controllers/changeEmailAdmin.controller.ts
import { Body, Controller, UseGuards, Request, Res, HttpStatus, ForbiddenException, Patch, NotFoundException } from '@nestjs/common';
import { UserService } from '../../user.service';
import { User, UserRole } from '../../user.entity';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse, ApiBody } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ActiveUserGuard } from '../../active-user-guard';
import { ChangeEmailAdminDto } from 'src/user/dto/change-email-admin.dto';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/admin')
export class ChangeEmailAdminController {
    constructor(
        private userService: UserService,
    ) { }

    // CHANGE USER EMAIL
    // "users" cannot change the email for anyone
    // "admin" can change the email for any user
    // "root" (super_admin) can change the email for any user/admin/root (all users)
    @Patch('/change-email')
    @ApiTags('Admin')
    @ApiOperation({ summary: 'Change a user email' })
    @ApiOkResponse({
        description: 'Email updated to {email} for {user}',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Email updated to {email} for {user}'
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
        description: '"<b>users</b>" cannot change the email for anyone <br>\
        "<b>admin</b>" can change the email for any basic user <br>\
        "<b>root</b>" (super_admin) can change the email for any user/admin/root (all users) <br>\
        <br>\
        "<b>deactivateUser</b>": This determines if the user account should be reactivated after changing the email, requiring the user to verify the new email <br><br>',
        type: ChangeEmailAdminDto
    })
    async changeEmail(@Request() req, @Body() changeEmailAdminDto: ChangeEmailAdminDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        
        let userToChange: User;     
    
        try {
            if (!isNaN(Number(changeEmailAdminDto.userOrIdToChange))) {
                userToChange = await this.userService.findOneById(changeEmailAdminDto.userOrIdToChange);
            } else {
                userToChange = await this.userService.findOneByUsername(changeEmailAdminDto.userOrIdToChange);
            }            
        } catch (error) {
            throw new NotFoundException(['User not found']);
        }
    
        switch (connectedUser.role) {
            case UserRole.ROOT:
                userToChange.email = changeEmailAdminDto.newEmail;
                break;
    
            case UserRole.ADMIN:
                if (userToChange.role !== UserRole.ROOT && userToChange.role !== UserRole.ADMIN) {
                    userToChange.email = changeEmailAdminDto.newEmail;
                } else {
                    throw new ForbiddenException(["Admins cannot change the email of a admin/root user"]);
                }
                break;
    
            case UserRole.USER:
                throw new ForbiddenException(['You do not have permission to perform this action']);
        }

        // Check if the admin want to deactivate the account to confirm the email
        if (changeEmailAdminDto.deactivateUser){
            await this.userService.changeActived( userToChange.id, false );
        }
    
        await this.userService.changeEmail( userToChange.id, changeEmailAdminDto.newEmail );
        return res.status(HttpStatus.OK).send({
            message:  ['Email changed successfully'],
            error: "",
            statusCode: 200
        });
    }
        
}
