"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthController = void 0;
const common_1 = require("@nestjs/common");
const auth_service_1 = require("./auth.service");
const swagger_1 = require("@nestjs/swagger");
const user_service_1 = require("../user/user.service");
const create_user_dto_1 = require("../user/dto/create-user.dto");
const login_user_dto_1 = require("../user/dto/login-user.dto");
const mail_service_1 = require("./mail.service");
const typeorm_1 = require("@nestjs/typeorm");
const user_entity_1 = require("../user/user.entity");
const typeorm_2 = require("typeorm");
const jwt_strategy_1 = require("./jwt.strategy");
const bcrypt = require("bcrypt");
const forgot_password_dto_1 = require("./dto/forgot-password.dto");
const reset_password_dto_1 = require("./dto/reset-password.dto");
let AuthController = exports.AuthController = class AuthController {
    constructor(userRepository, authService, userService, mailService, jwtStrategy) {
        this.userRepository = userRepository;
        this.authService = authService;
        this.userService = userService;
        this.mailService = mailService;
        this.jwtStrategy = jwtStrategy;
    }
    async register(createUserDto, res) {
        const user = await this.userService.create(createUserDto);
        return this.sendVerifyEmail(user, res);
    }
    async login(loginUserDto, res) {
        const result = await this.authService.login(loginUserDto.usernameOrEmail, loginUserDto.password, res);
        return res.status(common_1.HttpStatus.OK).send(result);
    }
    async verifyEmail(body, res) {
    }
    async sendVerifyEmail(user, res) {
        const resetToken = this.authService.generateResetToken(user);
        const resetLink = `${process.env.FRONT_END_URL}/reset-password?token=${resetToken}`;
        const emailContent = `To activate your account, please click the following link: \n ${resetLink}`;
        await this.mailService.sendMail(user.email, process.env.APP_NAME + " | RECOVERY PASSWORD", emailContent);
        return res.status(common_1.HttpStatus.OK).send({ message: ['Email sended successfully'] });
    }
    async forgotPassword(res, forgotPasswordDto) {
        const email = forgotPasswordDto.email;
        const user = await this.userService.findOneByEmail(email);
        if (!user) {
            return res.status(common_1.HttpStatus.NOT_FOUND).send({ message: ['User not found with provided email'] });
        }
        const resetToken = this.authService.generateResetToken(user);
        const resetLink = `${process.env.FRONT_END_URL}/reset-password?token=${resetToken}`;
        const emailContent = `To reset your password, please click the following link: \n ${resetLink}`;
        await this.mailService.sendMail(email, process.env.APP_NAME + " | RECOVERY PASSWORD", emailContent);
        return res.status(common_1.HttpStatus.OK).send({ message: ['Email sended successfully'] });
    }
    async resetPassword(res, resetPasswordDto) {
        const { recoveryCode, newPassword, confirmPassword } = resetPasswordDto;
        if (newPassword !== confirmPassword) {
            return res.status(common_1.HttpStatus.BAD_REQUEST).send({ message: ['New password and confirm password do not match'] });
        }
        let decoded;
        try {
            decoded = await this.jwtStrategy.decode(recoveryCode);
        }
        catch (error) {
            return res.status(common_1.HttpStatus.BAD_REQUEST).send({ message: ['Invalid recovery code'] });
        }
        if (decoded.isPasswordReset === false) {
            return res.status(common_1.HttpStatus.BAD_REQUEST).send({ message: ['This code is not for password resetting'] });
        }
        if (decoded.exp < Math.floor(Date.now() / 1000)) {
            return res.status(common_1.HttpStatus.BAD_REQUEST).send({ message: ['This code is expired'] });
        }
        const user = await this.userService.findOneByUsername(decoded.username);
        if (!user) {
            return res.status(common_1.HttpStatus.NOT_FOUND).send({ message: ['Invalid recovery code'] });
        }
        const salt = await bcrypt.genSalt();
        user.password = await bcrypt.hash(newPassword, salt);
        await this.userRepository.save(user);
        return res.status(common_1.HttpStatus.OK).send({ message: ['Password reset successfully'] });
    }
};
__decorate([
    (0, common_1.Post)('/register'),
    (0, swagger_1.ApiOperation)({ summary: 'Register a user' }),
    (0, swagger_1.ApiCreatedResponse)({
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
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 409, description: 'Username or email conflict' }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [create_user_dto_1.CreateUserDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_1.Post)('/login'),
    (0, swagger_1.ApiOperation)({ summary: 'Log-in' }),
    (0, swagger_1.ApiOkResponse)({
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
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'No user found with username or email' }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [login_user_dto_1.LoginUserDto, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_1.Post)('/activate-account'),
    (0, swagger_1.ApiOperation)({ summary: 'Verify email to activate the account' }),
    (0, swagger_1.ApiOkResponse)({
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
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'User not found' }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "verifyEmail", null);
__decorate([
    (0, common_1.Post)('/verify-email'),
    (0, swagger_1.ApiOperation)({ summary: 'Send code account verification to the email' }),
    (0, swagger_1.ApiOkResponse)({
        description: 'Email sended successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Email sended successfully'
                }
            }
        }
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'User not found' }),
    __param(0, (0, common_1.Body)()),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [user_entity_1.User, Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "sendVerifyEmail", null);
__decorate([
    (0, common_1.Post)('/forgot-password'),
    (0, swagger_1.ApiOperation)({ summary: 'Send recovery code request to a email' }),
    (0, swagger_1.ApiOkResponse)({
        description: 'Email sended successfully',
        schema: {
            type: 'object',
            properties: {
                message: {
                    type: 'string',
                    example: 'Email sended successfully'
                }
            }
        }
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'No user found with email {email}' }),
    __param(0, (0, common_1.Res)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, forgot_password_dto_1.ForgotPasswordDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "forgotPassword", null);
__decorate([
    (0, common_1.Post)('/reset-password'),
    (0, swagger_1.ApiOperation)({ summary: 'Set new password with recovery code from email' }),
    (0, swagger_1.ApiOkResponse)({
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
    }),
    (0, swagger_1.ApiResponse)({ status: 400, description: 'Bad request' }),
    (0, swagger_1.ApiResponse)({ status: 404, description: 'Invalid recovery code' }),
    __param(0, (0, common_1.Res)()),
    __param(1, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object, reset_password_dto_1.ResetPasswordDto]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "resetPassword", null);
exports.AuthController = AuthController = __decorate([
    (0, swagger_1.ApiTags)('Auth'),
    (0, common_1.Controller)('/auth'),
    __param(0, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __metadata("design:paramtypes", [typeorm_2.Repository,
        auth_service_1.AuthService,
        user_service_1.UserService,
        mail_service_1.MailService,
        jwt_strategy_1.JwtStrategy])
], AuthController);
//# sourceMappingURL=auth.controller.js.map