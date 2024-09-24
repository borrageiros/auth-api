// src/auth/resetPassword.controller.ts
import { Controller, Body, Post, HttpStatus, Res, Req, BadRequestException } from '@nestjs/common';
import { ApiTags, ApiResponse, ApiOperation, ApiOkResponse } from '@nestjs/swagger';
import { UserService } from 'src/user/user.service';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/user.entity';
import { Repository } from 'typeorm';
import { JwtStrategy } from '../jwt.strategy';
import * as bcrypt from 'bcrypt';
import { ResetPasswordDto } from '../dto/reset-password.dto';

@ApiTags('Auth')
@Controller('/auth')
export class ResetPasswordController {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
        private userService: UserService,
        private jwtStrategy: JwtStrategy
    ) { }
 
    // RESET PASSWORD | SET NEW PASSWORD
    @Post('/reset-password')
    @ApiOperation({ summary: 'Set new password with recovery code from email' })
    @ApiOkResponse({
        description: 'Password reset successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Password reset successfully'
                }
            }
        }
    })
    @ApiResponse({ status: 400, description: 'Bad request' })
    @ApiResponse({ status: 404, description: 'Invalid recovery code' })
    async resetPassword(@Res() res, @Req() req, @Body() resetPasswordDto: ResetPasswordDto) {
        const { recoveryCode, newPassword, confirmPassword } = resetPasswordDto;

        if (newPassword !== confirmPassword) {
            throw new BadRequestException(['New password and confirm password do not match']);
        }

        // Verify jwtToken
        let decoded;
        try {
            decoded = await this.jwtStrategy.decode(recoveryCode);
        } catch (error) {
            throw new BadRequestException(['Invalid recovery code']);
        }

        // Check token type
        if (decoded.isPasswordReset === false) {
            throw new BadRequestException(['This code is not for password resetting']);
        }

        // Check if token is expired
        if (decoded.exp < Math.floor(Date.now() / 1000)) {
            throw new BadRequestException(['This code is expired']);
        }

        const user = await this.userService.findOneByUsername(decoded.username);
        if (!user) {
            throw new BadRequestException(['Invalid recovery code']);
        }

        // Update password
        const salt = await bcrypt.genSalt();
        user.password = await bcrypt.hash(newPassword, salt);
        await this.userRepository.save(user);

        return res.status(HttpStatus.OK).send({
            message: ['Password reset successfully'],
            error: "",
            statusCode: 200
        });
    }
}