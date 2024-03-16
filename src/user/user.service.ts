import { Injectable } from "@nestjs/common";
import { Prisma, User } from "@prisma/client";
import { PrismaService } from "../database/prisma.service";

@Injectable()
export class UserService {
	constructor(private readonly prisma: PrismaService) {}

	async create(data: Prisma.UserCreateInput): Promise<User> {
		const newUser = await this.prisma.user.create({
			data
		});

		return newUser;
	}

	async findByEmail(email: string): Promise<User | null> {
		const user = await this.prisma.user.findUnique({
			where: { email }
		});

		return user;
	}

	async update(where: Prisma.UserWhereUniqueInput, updateDto: Prisma.UserUpdateInput) {
		return await this.prisma.user.update({ where, data: updateDto });
	}
}
