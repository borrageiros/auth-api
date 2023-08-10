// src/user/user.controller.ts
import { Body, Controller, Post, UseGuards, Request, BadRequestException, UnauthorizedException, Res, HttpStatus, ConflictException } from '@nestjs/common';
import { UserService } from './user.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ChangeUsernameDto } from './dto/change-username.dto';
import { AuthService } from 'src/auth/auth.service';

@ApiTags('Users')
@Controller('/users')
export class UserController {
    constructor(
        private userService: UserService,
        private authService: AuthService
    ) { }



    //////////////////////// CHANGE USERNAME
    @UseGuards(AuthGuard('jwt'))
    @ApiBearerAuth()
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
}
