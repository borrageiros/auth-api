// src/user/controllers/changeUsername.controller.ts
import { Body, Controller, UseGuards, Request, BadRequestException, UnauthorizedException, Res, HttpStatus, ConflictException, Patch } from '@nestjs/common';
import { UserService } from '../../user.service';
import { ApiTags, ApiResponse, ApiOperation, ApiBearerAuth, ApiOkResponse } from '@nestjs/swagger';
import { AuthGuard } from '@nestjs/passport';
import { ChangeUsernameDto } from '../../dto/change-username.dto';
import { AuthService } from 'src/auth/auth.service';
import { ActiveUserGuard } from '../../active-user-guard';

@UseGuards(AuthGuard('jwt'), ActiveUserGuard) // Check JwtToken (auth) and check if the user is activated
@ApiBearerAuth()
@Controller('/users')
export class ChangeUsernameController {
    constructor(
        private userService: UserService,
        private authService: AuthService,
    ) { }

    // CHANGE USERNAME
    @Patch('/change-username')
    @ApiTags('User')
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
    @ApiResponse({ status: 404, description: 'Not found' })
    @ApiResponse({ status: 409, description: 'Conflict' })
    async changeUsername(@Request() req, @Body() changeUsernameDto: ChangeUsernameDto, @Res() res) {
        const connectedUser = await this.userService.findOneById(req.user.userId);

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

        return res.status(HttpStatus.OK).send({
            message:  ['Username changed successfully'],
            error: "",
            statusCode: 200
        });
    }
        
}
