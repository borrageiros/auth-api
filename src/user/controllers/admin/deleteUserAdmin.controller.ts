// src/user/controllers/deleteUserAdmin.controller.ts
import { Controller, UseGuards, Request, Res, HttpStatus, Param, Delete, NotFoundException, ForbiddenException } from '@nestjs/common';
import { UserService } from '../../user.service';
import { UserRole } from '../../user.entity';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse, ApiParam } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ActiveUserGuard } from '../../active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/admin')
export class DeleteUserAdminController {
    constructor(
        private userService: UserService,
    ) { }

    // DELETE USER
    // "users" cannot delete the account of anyone
    // "admin" can delete the account of any user
    // "root" (super_admin) can delete the account of any user/admin/root (all users)
    @Delete('/delete/:username')
    @ApiTags('Admin')
    @ApiOperation({ summary: 'Delete a user account' })
    @ApiOkResponse({
        description: 'Account deleted successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Account deleted successfully'
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 403, description: 'Forbidden' })
    @ApiResponse({ status: 404, description: 'Not found' })
    @ApiParam({
        name: "username",
        description: 'The username of the account to delete. <br>\
        "<b>users</b>" cannot delete the account of anyone <br>\
        "<b>admin</b>" can delete the account of any user <br>\
        "<b>root</b>" (super_admin) can delete the account of any user/admin/root (all users) <br><br>',
        type: String,
        required: true
    })
    async deleteUser(@Param('username') username: string, @Request() req, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        
        let userToDelete;
        try {          
            userToDelete = await this.userService.findOneByUsername(username);
        } catch (error) {
            throw new NotFoundException(['User not found']);
        }

        if (connectedUser.role === UserRole.ROOT) {
            await this.userService.deleteOneById(userToDelete.id);
        } else if (connectedUser.role === UserRole.ADMIN && (userToDelete.role === UserRole.ROOT || userToDelete.role === UserRole.ADMIN)) {
            throw new ForbiddenException(['You do not have permission to perform this action']);
        } else if (connectedUser.role === UserRole.ADMIN && userToDelete.role !== UserRole.ROOT && userToDelete.role !== UserRole.ADMIN) {
            await this.userService.deleteOneById(userToDelete.id);
        } else {
            throw new ForbiddenException(['You do not have permission to perform this action']);
        }        

        return res.status(HttpStatus.OK).send({
            message:  ['Account deleted successfully'],
            error: "",
            statusCode: 200
        });
    }
        
}
