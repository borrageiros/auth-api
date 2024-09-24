// src/user/controllers/deleteUser.controller.ts
import { Controller, UseGuards, Request, Res, HttpStatus, Delete } from '@nestjs/common';
import { UserService } from '../../user.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ActiveUserGuard } from '../../active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/users')
export class DeleteUserController {
    constructor(
        private userService: UserService,
    ) { }

    // DELETE USER
    @Delete('/profile')
    @ApiTags('User')
    @ApiOperation({ summary: 'Delete user account' })
    @ApiOkResponse({
        description: 'User deleted successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'User deleted successfully'
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'Not found' })
    async delete( @Res() res, @Request() req ) {
        const result = await this.userService.deleteOneById(req.user.userId);
        return res.status(HttpStatus.OK).send({
            message:  "User deleted successfully",
            error: "",
            statusCode: 200
        });
    }  
        
}
