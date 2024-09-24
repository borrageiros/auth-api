// src/user/controllers/getUser.controller.ts
import { Controller, UseGuards, Res, Req, HttpStatus, Get, Query, NotFoundException, ForbiddenException } from '@nestjs/common';
import { UserService } from '../../user.service';
import { UserRole, PublicUserInfo } from '../../user.entity';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiQuery } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { plainToClass } from 'class-transformer';
import { ActiveUserGuard } from '../../active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/users')
export class GetUserController {
    constructor(
        private userService: UserService,
    ) { }

    // GET ONE USER (PUBLIC INFO)
    @Get()
    @ApiTags('User')
    @ApiOperation({ summary: 'Get a specific user by username or all users if no username provided' })
    @ApiQuery({
        name: "username",
        description: 'The username to search for.<ul> <br>\
            <li>If you are an "root", it will provide you with the private information of all users.</li> <br>\
            <li>If it is an "admin", it will provide you with the private information of all users except the "root" users, which will return public information.</li> <br>\
            <li>For basic users, the system will hide the accounts labeled as "root" or "admin", and will only display the publicly information of the basic users.</li> <br>\
            </ul>',
        type: String,
        required: false
    })
    @ApiQuery({
        name: "index",
        description: "Determines the starting index for counting users alphabetically (default 1).",
        type: Number,
        required: false
    })
    @ApiQuery({
        name: "number",
        description: "Determines the number of users that will be returned starting from the specified index (default 15).",
        type: Number,
        required: false
    })    
    @ApiResponse({ status: 200, description: 'User public info (Object or Array)' })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'Not found' })
    async getUserByUsername( @Res() res, @Req() req, @Query('username') username?: string, @Query('index') index?: number, @Query('number') number?: number ) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        if (username) {
            let user;
            try {
                user = await this.userService.findOneByUsername(username);
                delete user.password;
            } catch (error) {
                throw new NotFoundException(["User not found"]);
            }

            // 
            // If you are an "root", it will provide you with the private information of all users.
            // If it is an "admin", it will provide you with the private information of all users except the "root" users, which will return public information.
            // For basic users, the system will hide the accounts labeled as "root" or "admin", and will only display the publicly information of the basic users.
            //
            if ( connectedUser.role === UserRole.ROOT ){
                return res.status(HttpStatus.OK).send({
                    message: [user],
                    error: "",
                    statusCode: 200
                });
            } else if ( connectedUser.role === UserRole.ADMIN && user.role === UserRole.ROOT) {
                return res.status(HttpStatus.OK).send({
                    message: [plainToClass(PublicUserInfo, user)],
                    error: "",
                    statusCode: 200
                });
            } else if ( connectedUser.role === UserRole.ADMIN && user.role !== UserRole.ROOT) {
                return res.status(HttpStatus.OK).send({
                    message: [user],
                    error: "",
                    statusCode: 200
                });
            } else {
                if ( user.role === UserRole.ROOT || user.role === UserRole.ADMIN) {
                    throw new ForbiddenException(['You do not have permission to perform this action']);
                } else {
                    return res.status(HttpStatus.OK).send({
                        message: [plainToClass(PublicUserInfo, user)],
                        error: "",
                        statusCode: 200
                    });
                }
            }
        } else {
            let users;
            try {
                users = await this.userService.findUsers(index ? index : 1, number ? number : 15);
                users = users.map(user => {
                    const { password, ...userWithoutPassword } = user;
                    return userWithoutPassword;
                });
            } catch (error) {
                throw new NotFoundException(["Users not found"]);
            }

            // 
            // If you are an "root", it will provide you with the private information of all users.
            // If it is an "admin", it will provide you with the private information of all users except the "root" users, which will return public information.
            // For basic users, the system will hide the accounts labeled as "root" or "admin", and will only display the publicly information of the basic users.
            //
            if ( connectedUser.role === UserRole.ROOT ){
                return res.status(HttpStatus.OK).send({
                    message: [users],
                    error: "",
                    statusCode: 200
                });
            } else if ( connectedUser.role === UserRole.ADMIN ) {
                const noRootUsers = users.filter(user => user.role !== UserRole.ROOT);
                const rootUsers = users.filter(user => user.role === UserRole.ROOT);
                const combined = noRootUsers.concat(plainToClass(PublicUserInfo, rootUsers));
                return res.status(HttpStatus.OK).send({
                    message: [combined],
                    error: "",
                    statusCode: 200
                });
            } else {
                const noRootAdminUsers = users.filter(user => user.role !== UserRole.ROOT && user.role !== UserRole.ADMIN);
                return res.status(HttpStatus.OK).send({
                    message: [plainToClass(PublicUserInfo, noRootAdminUsers)],
                    error: "",
                    statusCode: 200
                });
            }
        }
    }    
        
}
