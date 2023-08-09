// src/user/user.service.ts
import { Injectable, ConflictException, BadRequestException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UserService {
    constructor(
        @InjectRepository(User) private userRepository: Repository<User>,
    ) { }

    async findOneByUsername(username: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { username } });
        if (!user) {
          throw new NotFoundException(`No user found with username ${username}`);
        }
        return user;
    }

    async findOneByEmail(email: string): Promise<User> {
        const user = await this.userRepository.findOne({ where: { email } });
        if (!user) {
          throw new NotFoundException(`No user found with email ${email}`);
        }
        return user;
    }

    // SIGN UP
    async create(createUserDto: CreateUserDto): Promise<any> {
        const user = new User();
        user.username = createUserDto.username;
        user.email = createUserDto.email;

        const salt = await bcrypt.genSalt();
        user.password = await bcrypt.hash(createUserDto.password, salt);

        try {
            await this.userRepository.save(user);
            const { password, ...result } = createUserDto;  // Excluyendo password del DTO
            return result;
        } catch (error) {
            // EL RESTO DE ERRORES SE MANEJAN DESDE EL DTO "./dto/create-user.dto"
            if (error.code === 'ER_DUP_ENTRY') {
                if (error.sqlMessage.includes(user.username)) {
                    throw new ConflictException('Username already in use');
                } else if (error.sqlMessage.includes(user.email)) {
                    throw new ConflictException('Email already in use');
                } else {
                    throw new ConflictException('Duplicate entry');
                }
            } else {
                throw new BadRequestException('Undefined error');
            }
        }
    }
}
