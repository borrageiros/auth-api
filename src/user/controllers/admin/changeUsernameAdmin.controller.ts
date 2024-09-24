// src/user/controllers/changeUsernameAdmin.controller.ts
import { Body, Controller, UseGuards, Request, Res, HttpStatus, ForbiddenException, Patch, NotFoundException } from '@nestjs/common';
import { UserService } from '../../user.service';
import { User, UserRole } from '../../user.entity';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse, ApiBody } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ActiveUserGuard } from '../../active-user-guard';
import { ChangeUsernameAdminDto } from 'src/user/dto/change-username-admin.dto';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/admin')
export class ChangeUsernameAdminController {
    constructor(
        private userService: UserService,
    ) { }

    // CHANGE USER USERNAME
    // "users" cannot change the username for anyone
    // "admin" can change the username for any user
    // "root" (super_admin) can change the username for any user/admin/root (all users)
    @Patch('/change-username')
    @ApiTags('Admin')
    @ApiOperation({ summary: 'Change a user username' })
    @ApiOkResponse({
        description: 'Username updated to {username} for {user}',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Username updated to {username} for {user}'
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
        description: '"<b>users</b>" cannot change the username for anyone <br>\
        "<b>admin</b>" can change the username for any basic user <br>\
        "<b>root</b>" (super_admin) can change the username for any user/admin/root (all users) <br><br>',
        type: ChangeUsernameAdminDto
    })
    async changeUsername(@Request() req, @Body() changeUsernameAdminDto: ChangeUsernameAdminDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        
        let userToChange: User;     
    
        try {
            if (!isNaN(Number(changeUsernameAdminDto.userOrIdToChange))) {
                userToChange = await this.userService.findOneById(changeUsernameAdminDto.userOrIdToChange);
            } else {
                userToChange = await this.userService.findOneByUsername(changeUsernameAdminDto.userOrIdToChange);
            }            
        } catch (error) {
            throw new NotFoundException(['User not found']);
        }
    
        switch (connectedUser.role) {
            case UserRole.ROOT:
                userToChange.username = changeUsernameAdminDto.newUsername;
                break;
    
            case UserRole.ADMIN:
                if (userToChange.role !== UserRole.ROOT && userToChange.role !== UserRole.ADMIN) {
                    userToChange.username = changeUsernameAdminDto.newUsername;
                } else {
                    throw new ForbiddenException(["Admins cannot change the username of a admin/root user"]);
                }
                break;
    
            case UserRole.USER:
                throw new ForbiddenException(['You do not have permission to perform this action']);
        }
    
        await this.userService.changeUsername( userToChange.id, changeUsernameAdminDto.newUsername );
        return res.status(HttpStatus.OK).send({
            message:  ['Username changed successfully'],
            error: "",
            statusCode: 200
        });
    }
        
}
