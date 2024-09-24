// src/user/controllers/getUsers.controller.ts
import { Controller, UseGuards, Res, HttpStatus, Get, Query, NotFoundException } from '@nestjs/common';
import { UserService } from '../../user.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse, ApiQuery } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ActiveUserGuard } from '../../active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/users')
export class GetUsersController {
    constructor(
        private userService: UserService,
    ) { }

    // GET USERS
    @Get('/search')
    @ApiTags('User')
    @ApiOperation({ summary: 'Get a list of users by username or email, case insensitive and use the function LIKE from mysql ' })
    @ApiOkResponse({
        description: 'List of usernames matching the search term',
        schema: {
            type: 'object',
            properties: {
                users: {
                    type: 'array',
                    items: {
                        type: 'string'
                    },
                    example: ["user1", "user2", "user3"]
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'Not found' })
    @ApiQuery({ name: "username", description: "The username to search for.", type: String, required: false})
    @ApiQuery({ name: "email", description: "The email to search for.", type: String, required: false})
    async searchUsersByUsername( @Res() res, @Query('username') username?: string, @Query('email') email?: string ) {
        let users = []
        try{
            users = await this.userService.findUsersByEmail(email);
            return res.status(HttpStatus.OK).send({
                message:  users,
                error: "",
                statusCode: 200
            });
        }catch {
            try {
                users = await this.userService.findUsersByUsername(username);
            } catch (error) {
                throw new NotFoundException([error.message]);
            }
            return res.status(HttpStatus.OK).send({
                message:  users,
                error: "",
                statusCode: 200
            });
        }

    }
        
}
