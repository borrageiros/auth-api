// src/user/controllers/getProfile.controller.ts
import { Controller, UseGuards, Request, Res, HttpStatus, Get } from '@nestjs/common';
import { UserService } from '../../user.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ActiveUserGuard } from '../../active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/users')
export class GetProfileController {
    constructor(
        private userService: UserService,
    ) { }

    // GET USER PROFILE FOR CONNECTED USER (PRIVATE INFO)
    @Get("/profile")
    @ApiTags('User')
    @ApiOperation({ summary: 'Get user profile by connected user (Private/All Info)' })
    @ApiResponse({ status: 200, description: 'User all info (Object)' })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 401, description: 'Unauthorized' })
    @ApiResponse({ status: 404, description: 'Not found' })
    async getUserByToken( @Res() res, @Request() req ) {
        const connectedUser = await this.userService.findOneById(req.user.userId);
        delete connectedUser.password;
        return res.status(HttpStatus.OK).send({
            message: connectedUser,
            error: "",
            statusCode: 200
        });
    }
        
}
