// src/auth/login.controller.ts
import { Controller, Body, Post, HttpStatus, Res, UseGuards } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { ApiTags, ApiResponse, ApiOperation, ApiOkResponse } from '@nestjs/swagger';
import { LoginUserDto } from 'src/user/dto/login-user.dto';
import { ActiveUserGuard } from 'src/user/active-user-guard';

@ApiTags('Auth')
@Controller('/auth')
export class LoginController {
    constructor(
        private authService: AuthService,
    ) { }
 
    // LOG-IN
    @UseGuards( ActiveUserGuard )
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
    @ApiResponse({ status: 401, description: 'Incorrect password' })
    @ApiResponse({ status: 404, description: 'No user found with username or email' })
    async login(@Body() loginUserDto: LoginUserDto, @Res() res) {
        const data = await this.authService.login(loginUserDto.usernameOrEmail, loginUserDto.password, res);
        return res.status(HttpStatus.OK).send({
            message: data,
            error: "",
            statusCode: 200
        });
    }
}