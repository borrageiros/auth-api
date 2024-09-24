// src/auth/activateAccount.controller.ts
import { Controller, Get, HttpStatus, Res, Req, BadRequestException, NotFoundException, Param } from '@nestjs/common';
import { ApiTags, ApiResponse, ApiOperation, ApiOkResponse, ApiParam } from '@nestjs/swagger';
import { UserService } from 'src/user/user.service';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/user.entity';
import { Repository } from 'typeorm';
import { JwtStrategy } from '../jwt.strategy';

@ApiTags('Auth')
@Controller('/auth')
export class ActivateAccountController {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        private userService: UserService,
        private jwtStrategy: JwtStrategy
    ) { }

    // VERIFY EMAIL
    @Get('/activate-account/:activateCode')
    @ApiOperation({ summary: 'Verify email to activate the account' })
    @ApiOkResponse({
        description: 'Account verified',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Account verified'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 404, description: 'User not found' })
    @ApiParam({ name: "activateCode", description: "The code to activate the account", type: String })
    async verifyEmail(@Param('activateCode') activateCode: string, @Res() res, @Req() req): Promise<any> {
        // Verify jwtToken
        let decoded;
        try {
            decoded = await this.jwtStrategy.decode(activateCode);
        } catch (error) {
            throw new BadRequestException(['Invalid activation code']);
        }

        // Check token type
        if (decoded.isActivationCode === false) {
            throw new BadRequestException(['This code is not for activate the account']);
        }

        // Check if token is expired
        if (decoded.exp < Math.floor(Date.now() / 1000)) {
            throw new BadRequestException(['This code is expired']);

        }

        const user = await this.userService.findOneByUsername(decoded.username);
        if (!user) {
            throw new NotFoundException(['Invalid activate code']);
        }

        // Activate the user
        user.actived = true;
        await this.userRepository.save(user);

        // Check if request is coming from a browser
        if (req.headers.accept.includes('text/html')) {
            // If request comes from a browser, redirect to redirectUrl
            return res.redirect(decoded.redirectUrl);
        } else {
            // If request is not from a browser, send a JSON response
            return res.status(HttpStatus.OK).send({
                message: 'Account verified',
                error: '',
                statusCode: 200
            });
        }
    }
}