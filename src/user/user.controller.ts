// src/user/user.controller.ts
import { Body, Controller, Post, UseGuards, Request, BadRequestException, UnauthorizedException, Res, HttpStatus, ConflictException, Get, Query, ForbiddenException, Patch, NotFoundException } from '@nestjs/common';
import { UserService } from './user.service';
import { User, UserRole, PublicUserInfo } from './user.entity';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse, ApiQuery } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ChangeUsernameDto } from './dto/change-username.dto';
import { AuthService } from 'src/auth/auth.service';
import { plainToClass } from 'class-transformer';
import { ChangeEmailDto } from './dto/change-email.dto';
import { ChangeRoleDto } from './dto/change-role.dto';
import { ActiveUserGuard } from './active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/users')
export class UserController {
    constructor(
        private userService: UserService,
        private authService: AuthService
    ) { }



    //////////////////////// GET ONE USER (PUBLIC INFO)
    @Get()
    @ApiTags('Users')
    @ApiOperation({ summary: 'Get a specific user by username or all users if no username provided (Public Info)' })
    @ApiQuery({ name: "username", description: "The username to search for.", type: String, required: false})
    @ApiResponse({ status: 200, description: 'User public info (Object or Array)' })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'Not found' })
    async getUserByUsername( @Res() res, @Query('username') username?: string ) {
        try {
            if (username) {
                const user = await this.userService.findOneByUsername(username);
                return res.status(HttpStatus.OK).send(plainToClass(PublicUserInfo, user));
            } else {
                const users = await this.userService.findAllUsers();
                return res.status(HttpStatus.OK).send({users: plainToClass(PublicUserInfo, users)});
            }
        } catch (error) {
            return res.status(HttpStatus.NOT_FOUND).send({ message: error.message });
        }
    }    
    ////////////////////////



    //////////////////////// GET USER PROFILE FOR CONNECTED USER (PRIVATE INFO)
    @Get("/profile")
    @ApiTags('Users')
    @ApiOperation({ summary: 'Get user profile by connected user (Private/All Info)' })
    @ApiResponse({ status: 200, description: 'User all info (Object)' })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    async getUserByToken( @Res() res, @Request() req ) {
        const connectedUser = await this.userService.findOneById(req.user.id);
        return res.status(HttpStatus.OK).send(connectedUser);
    }
    ////////////////////////



    //////////////////////// GET USERS
    @Get('/search')
    @ApiTags('Users')
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
            return res.status(HttpStatus.OK).send(users);
        }catch {
            try {
                users = await this.userService.findUsersByUsername(username);
            } catch (error) {
                return res.status(HttpStatus.NOT_FOUND).send({ message: error.message });
            }
            return res.status(HttpStatus.OK).send(users);
        }

    }
    ////////////////////////



    //////////////////////// CHANGE USERNAME
    @Patch('/change-username')
    @ApiTags('Users')
    @ApiOperation({ summary: 'Change username' })
    @ApiOkResponse({
        description: 'Username changed successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'array',
                    items: {
                        type: 'string',
                        example: 'Username changed successfully'
                    }
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 409, description: 'Conflict' })
    async changeUsername(@Request() req, @Body() changeUsernameDto: ChangeUsernameDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.id);

        const newUsername = changeUsernameDto.newUsername;
        if (!newUsername) {
            throw new BadRequestException(['A new username must be provided.']);
        }

        //Check password
        const user = await this.authService.validateUser(connectedUser.username, changeUsernameDto.password, res)
        if (!user) {
            throw new UnauthorizedException(['Incorrect password']);
        }

        // Check if username exist and change it
        try {
            await this.userService.changeUsername( connectedUser.id, changeUsernameDto.newUsername );
        } catch (error) {
            if (error.sqlMessage.includes(changeUsernameDto.newUsername)) {
                throw new ConflictException(['Username already in use']);
            }
        }

        return res.status(HttpStatus.OK).send({ message: ['Username changed successfully'] });
    }
    ////////////////////////



    //////////////////////// CHANGE EMAIL
    @Patch('/change-email')
    @ApiTags('Users')
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
    @ApiResponse({ status: 409, description: 'Conflict' })
    async changeEmail(@Request() req, @Body() changeEmailDto: ChangeEmailDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.id);

        //Check password
        const user = await this.authService.validateUser(connectedUser.username, changeEmailDto.password, res)
        if (!user) {
            throw new UnauthorizedException(['Incorrect password']);
        }

        // Check if email exist and change it
        try {
            await this.userService.changeEmail( connectedUser.id, changeEmailDto.newEmail );
        } catch (error) {
            if (error.sqlMessage.includes(changeEmailDto.newEmail)) {
                throw new ConflictException(['Email already in use']);
            }
        }

        return res.status(HttpStatus.OK).send({ message: ['Email changed successfully'] });
    }
    ////////////////////////



    //////////////////////// CHANGE USER ROL
    // "users" cannot change the role for anyone
    // "admin" can change the role for any user/admin except removing or giving the root role (super_admin)
    // "root" (super_admin) can change the role for any user/admin/root
    @Patch('/admin/change-role')
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
    async changeRole(@Request() req, @Body() changeRoleDto: ChangeRoleDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.id);
        
        let userToChange: User;     
    
        try {
            if (!isNaN(Number(changeRoleDto.userOrIdToChange))) {
                userToChange = await this.userService.findOneById(Number(changeRoleDto.userOrIdToChange));
            } else {
                userToChange = await this.userService.findOneByUsername(changeRoleDto.userOrIdToChange);
            }            
        } catch (error) {
            return res.status(HttpStatus.NOT_FOUND).send({ message: ['User not found'] });
        }
    
        switch (connectedUser.role) {
            case UserRole.ROOT:
                userToChange.role = changeRoleDto.newRole;
                break;
    
            case UserRole.ADMIN:
                if (userToChange.role !== UserRole.ROOT) {
                    userToChange.role = changeRoleDto.newRole;
                } else {
                    return res.status(HttpStatus.FORBIDDEN).send({ message: ["Admins cannot change the role of a root user"] });
                }
                break;
    
            case UserRole.USER:
                return res.status(HttpStatus.FORBIDDEN).send({ message: ['You do not have permission to perform this action'] });
        }
    
        await this.userService.changeRole(userToChange.id, changeRoleDto.newRole);
        return res.status(HttpStatus.OK).send({ message: ['Role updated to ' + userToChange.role + ' for ' + userToChange.username] });
    }
    
}
