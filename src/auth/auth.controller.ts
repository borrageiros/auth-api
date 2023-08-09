// src/auth/auth.controller.ts
import { Controller, Body, Post, UseGuards, Get } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';

@Controller('/auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('/login')
    async login(@Body() body) {
        return this.authService.login(body.username, body.password);
    }

    @UseGuards(AuthGuard('jwt'))
    @Get('/prueba')
    async prueba() {
        return {
            esto: "esto mismisimo",
        };
    }
}
