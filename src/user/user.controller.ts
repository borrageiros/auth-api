// src/user/user.controller.ts
import { Body, Controller, Post, UseGuards, Request, BadRequestException, UnauthorizedException, Res, HttpStatus, ConflictException, Get, Query } from '@nestjs/common';
import { UserService } from './user.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ChangeUsernameDto } from './dto/change-username.dto';
import { AuthService } from 'src/auth/auth.service';
import { plainToClass } from 'class-transformer';
import { PublicUserInfo } from './dto/public-user-info.dto';
import { ChangeEmailDto } from './dto/change-email.dto';

@UseGuards(AuthGuard('jwt'))
@ApiBearerAuth()
@ApiTags('Users')
@Controller('/users')
export class UserController {
    constructor(
        private userService: UserService,
        private authService: AuthService
    ) { }



    //////////////////////// GET ONE USER (PUBLIC INFO)
    @Get()
    @ApiOperation({ summary: 'Get a specific user by username (Public Info)' })
    @ApiResponse({ status: 200, description: 'User public info (Object)' })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'Not found' })
    async getUserByUsername(@Query('username') username: string, @Res() res) {
        try{
            const user = await this.userService.findOneByUsername(username);
            return res.status(HttpStatus.OK).send(plainToClass(PublicUserInfo, user));  // Excluyendo datos privados del objeto User
        }catch (error){
            return res.status(HttpStatus.NOT_FOUND).send({ message: error.message });
        }
    }
    ////////////////////////



    //////////////////////// GET USER PROFILE FOR CONNECTED USER (PRIVATE INFO)
    @Get("/profile")
    @ApiOperation({ summary: 'Get user profile by connected user (Private/All Info)' })
    @ApiResponse({ status: 200, description: 'User all info (Object)' })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    async getUserByToken( @Res() res, @Request() req ) {
        const connectedUser = await this.userService.findUserById(req.user.id);
        return res.status(HttpStatus.OK).send(connectedUser);
    }
    ////////////////////////



    //////////////////////// GET USERS
    @Get('/search')
    @ApiOperation({ summary: 'Get users by username or email, case insensitive and use the function LIKE from mysql ' })
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
    async searchUsersByUsername(@Query('username') username: string, @Res() res) {
        let users = []
        try{
            users = await this.userService.findUsersByEmail(username);
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
    @Post('/change-username')
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
        const connectedUser = await this.userService.findUserById(req.user.id);

        const newUsername = changeUsernameDto.newUsername;
        if (!newUsername) {
            throw new BadRequestException(['A new username must be provided.']);
        }

        //Check password
        const token = await this.authService.validateUser(connectedUser.username, changeUsernameDto.password)
        if (!token) {
            throw new UnauthorizedException(['Incorrect password']);
        }

        // Check if username exist and change it
        try {
            await this.userService.changeUsernameConnectedUser( connectedUser.id, changeUsernameDto.newUsername );
        } catch (error) {
            if (error.sqlMessage.includes(changeUsernameDto.newUsername)) {
                throw new ConflictException(['Username already in use']);
            }
        }

        return res.status(HttpStatus.OK).send({ message: ['Username changed successfully'] });
    }
    ////////////////////////



    //////////////////////// CHANGE EMAIL
    @Post('/change-email')
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
        const connectedUser = await this.userService.findUserById(req.user.id);

        const newUsername = changeEmailDto.newEmail;
        if (!newUsername) {
            throw new BadRequestException(['A new email must be provided.']);
        }

        //Check password
        const token = await this.authService.validateUser(connectedUser.username, changeEmailDto.password)
        if (!token) {
            throw new UnauthorizedException(['Incorrect password']);
        }

        // Check if email exist and change it
        try {
            await this.userService.changeEmailConnectedUser( connectedUser.id, changeEmailDto.newEmail );
        } catch (error) {
            if (error.sqlMessage.includes(changeEmailDto.newEmail)) {
                throw new ConflictException(['Email already in use']);
            }
        }

        return res.status(HttpStatus.OK).send({ message: ['Username changed successfully'] });
    }
    ////////////////////////
}
