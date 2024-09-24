// src/user/controllers/changeRoleAdmin.controller.ts
import { Body, Controller, UseGuards, Request, Res, HttpStatus, ForbiddenException, Patch, NotFoundException } from '@nestjs/common';
import { UserService } from '../../user.service';
import { User, UserRole } from '../../user.entity';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse, ApiBody } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ChangeRoleDto } from '../../dto/change-role.dto';
import { ActiveUserGuard } from '../../active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/admin')
export class ChangeRoleController {
    constructor(
        private userService: UserService,
    ) { }

    // CHANGE USER ROL
    // "users" cannot change the role for anyone
    // "admin" cannot change the role for anyone
    // "root" (super_admin) can change the role for any user/admin/root
    @Patch('/change-role')
    @ApiTags('Admin')
    @ApiOperation({ summary: 'Change a user role' })
    @ApiOkResponse({
        description: 'Role updated to {role} for {user}',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Role updated to {role} for {user}'
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
        description: '"<b>users</b>" cannot change the role for anyone <br>\
        "<b>admin</b>" cannot change the role for anyone <br>\
        "<b>root</b>" (super_admin) can change the role for any user/admin/root <br><br>',
        type: ChangeRoleDto
    })
    async changeRole(@Request() req, @Body() changeRoleDto: ChangeRoleDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        
        let userToChange: User;     
    
        try {
            if (!isNaN(Number(changeRoleDto.userOrIdToChange))) {
                userToChange = await this.userService.findOneById(changeRoleDto.userOrIdToChange);
            } else {
                userToChange = await this.userService.findOneByUsername(changeRoleDto.userOrIdToChange);
            }            
        } catch (error) {
            throw new NotFoundException(['User not found']);
        }
    
        switch (connectedUser.role) {
            case UserRole.ROOT:
                userToChange.role = changeRoleDto.newRole;
                break;
    
            case UserRole.ADMIN:
                throw new ForbiddenException(["You do not have permission to perform this action"]);
    
            case UserRole.USER:
                throw new ForbiddenException(['You do not have permission to perform this action']);
        }
    
        await this.userService.changeRole(userToChange.id, changeRoleDto.newRole);
        return res.status(HttpStatus.OK).send({
            message:  ['Role updated to ' + userToChange.role + ' for ' + userToChange.username],
            error: "",
            statusCode: 200
        });
    }
        
}
