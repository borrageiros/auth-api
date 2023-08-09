// src/auth/auth.controller.ts
import { Controller, Body, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiTags, ApiResponse } from '@nestjs/swagger';

@ApiTags('Auth')
@Controller('/auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('/login')
    @ApiResponse({ status: 201, description: 'Log-in successfully'})
    async login(@Body() body) {
        return this.authService.login(body.username, body.password);
    }

}
