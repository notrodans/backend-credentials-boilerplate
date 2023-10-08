import { UseGuards, Controller, Post, HttpCode, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { JwtAuthGuard } from "../auth/guards/auth-guard";
import { User } from "../decorators/user.decorator";
import { UserService } from "./user.service";
import { User as UserType } from "@prisma/client";

@Controller("user")
export class UserController {
	constructor(private readonly userService: UserService, private readonly jwtService: JwtService) {}

	@UseGuards(JwtAuthGuard)
	@Post("profile")
	@HttpCode(200)
	async profile(@User() userInfo: UserType) {
		const user = await this.userService.findByEmail(userInfo.email);

		const { id, createdAt, updatedAt, refreshToken, password, ...newUser } = user;
		if (!user) {
			throw new UnauthorizedException();
		}
		return newUser;
	}
}
