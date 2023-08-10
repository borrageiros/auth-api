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
exports.UserService = void 0;
const common_1 = require("@nestjs/common");
const typeorm_1 = require("@nestjs/typeorm");
const typeorm_2 = require("typeorm");
const bcrypt = require("bcrypt");
const user_entity_1 = require("./user.entity");
let UserService = exports.UserService = class UserService {
    constructor(userRepository) {
        this.userRepository = userRepository;
    }
    async findUserById(id) {
        const user = await this.userRepository.findOne({ where: { id } });
        if (!user) {
            throw new common_1.NotFoundException(`No user found with ID ${id}`);
        }
        return user;
    }
    async findOneByUsername(username) {
        const user = await this.userRepository.findOne({ where: { username } });
        if (!user) {
            throw new common_1.NotFoundException(`No user found with username ${username}`);
        }
        return user;
    }
    async findUsersByUsername(username) {
        const users = await this.userRepository.find({
            where: {
                username: (0, typeorm_2.Like)(`%${username}%`)
            }
        });
        if (users.length === 0) {
            throw new common_1.NotFoundException(`No users found with username containing "${username}"`);
        }
        return { users: users.map(user => user.username) };
    }
    async findOneByEmail(email) {
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) {
            throw new common_1.NotFoundException(`No user found with email ${email}`);
        }
        return user;
    }
    async findUsersByEmail(email) {
        const users = await this.userRepository.find({
            where: {
                email: (0, typeorm_2.Like)(`%${email}%`)
            }
        });
        if (users.length === 0) {
            throw new common_1.NotFoundException(`No users found with email containing "${email}"`);
        }
        return { users: users.map(user => user.username) };
    }
    async changeUsernameConnectedUser(connectedUserId, newUsername) {
        const user = await this.userRepository.findOne({ where: { id: connectedUserId } });
        user.username = newUsername;
        await this.userRepository.save(user);
        return user;
    }
    async create(createUserDto) {
        const user = new user_entity_1.User();
        user.username = createUserDto.username;
        user.email = createUserDto.email;
        const salt = await bcrypt.genSalt();
        user.password = await bcrypt.hash(createUserDto.password, salt);
        try {
            await this.userRepository.save(user);
            const { password, ...result } = createUserDto;
            return result;
        }
        catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                if (error.sqlMessage.includes(user.username)) {
                    throw new common_1.ConflictException(['Username already in use']);
                }
                else if (error.sqlMessage.includes(user.email)) {
                    throw new common_1.ConflictException(['Email already in use']);
                }
                else {
                    throw new common_1.ConflictException(['Duplicate entry']);
                }
            }
            else {
                throw new common_1.BadRequestException(['Undefined error']);
            }
        }
    }
};
exports.UserService = UserService = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, typeorm_1.InjectRepository)(user_entity_1.User)),
    __metadata("design:paramtypes", [typeorm_2.Repository])
], UserService);
//# sourceMappingURL=user.service.js.map