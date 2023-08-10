// src/auth/auth.controller.ts
import { Controller, Body, Post, HttpStatus, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiTags, ApiResponse, ApiOperation, ApiOkResponse, ApiCreatedResponse } from '@nestjs/swagger';
import { UserService } from 'src/user/user.service';
import { CreateUserDto } from 'src/user/dto/create-user.dto';
import { LoginUserDto } from 'src/user/dto/login-user.dto';

@ApiTags('Auth')
@Controller('/auth')
export class AuthController {
    constructor(
        private authService: AuthService,
        private userService: UserService
    ) { }

    //////////////////////// REGISTER
    @Post('/register')
    @ApiOperation({ summary: 'Register a user' })
    @ApiCreatedResponse({
        description: 'User created',
        schema: {
            type: 'object',
            properties: {
                access_token: {
                    type: 'string',
                    example: 'string'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 409, description: 'Username or email conflict' })
    async register(@Body() createUserDto: CreateUserDto): Promise<any> {
        await this.userService.create(createUserDto);
        return this.authService.login(createUserDto.username, createUserDto.password);
    }
    ////////////////////////



    //////////////////////// LOG-IN
    @Post('/login')
    @ApiOperation({ summary: 'Log-in' })
    @ApiOkResponse({
        description: 'Log-in successfully',
        schema: {
            type: 'object',
            properties: {
                access_token: {
                    type: 'string',
                    example: 'string'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 404, description: 'No user found with username or email' })
    async login(@Body() loginUserDto: LoginUserDto, @Res() res) {
        const result = await this.authService.login(loginUserDto.usernameOrEmail, loginUserDto.password);
        return res.status(HttpStatus.OK).send(result);
    }
    ////////////////////////

}
