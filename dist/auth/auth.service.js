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
exports.AuthService = void 0;
const common_1 = require("@nestjs/common");
const jwt_1 = require("@nestjs/jwt");
const bcrypt = require("bcrypt");
const user_service_1 = require("../user/user.service");
const user_entity_1 = require("../user/user.entity");
const class_validator_1 = require("class-validator");
let AuthService = exports.AuthService = class AuthService {
    constructor(userService, jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }
    generateResetToken(user, type) {
        const payload = {
            sub: user.id,
            username: user.username,
            isActivationCode: false,
            isPasswordReset: false,
        };
        switch (type) {
            case "isActivationCode": {
                payload.isActivationCode = true;
            }
            case "isPasswordReset": {
                payload.isPasswordReset = true;
            }
        }
        return this.jwtService.sign(payload, {
            expiresIn: process.env.JWT_TOKEN_PASSWORD_RECOVERY_EXPIRE
        });
    }
    async validateUser(usernameOrEmail, password, res) {
        let user = new user_entity_1.User;
        if ((0, class_validator_1.isEmail)(usernameOrEmail)) {
            user = await this.userService.findOneByEmail(usernameOrEmail);
        }
        else {
            user = await this.userService.findOneByUsername(usernameOrEmail);
        }
        if (!user) {
            return res.status(common_1.HttpStatus.NOT_FOUND).send({ message: ['User not found'] });
        }
        if (user && await bcrypt.compare(password, user.password)) {
            return user;
        }
        return null;
    }
    async login(usernameOrEmail, password, res) {
        const user = await this.validateUser(usernameOrEmail, password, res);
        if (!user) {
            throw new common_1.UnauthorizedException(['Incorrect password']);
        }
        const payload = { username: user.username, sub: user.id };
        return {
            access_token: this.jwtService.sign(payload),
        };
    }
};
__decorate([
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], AuthService.prototype, "validateUser", null);
__decorate([
    __param(2, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, String, Object]),
    __metadata("design:returntype", Promise)
], AuthService.prototype, "login", null);
exports.AuthService = AuthService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [user_service_1.UserService,
        jwt_1.JwtService])
], AuthService);
//# sourceMappingURL=auth.service.js.map