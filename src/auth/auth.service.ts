import { BadRequestException, Injectable } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import { Role, User } from "@prisma/client";
import { hash, verify } from "argon2";
import { PrismaService } from "../database/prisma.service";
import { UserService } from "../user/user.service";
import { LoginDto } from "./dto/auth-login.dto";
import { AuthRegisterDto } from "./dto/auth-register.dto";
import { TokensDto } from "./dto/auth-token.dto";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService {
	constructor(
		private readonly userService: UserService,
		private readonly prisma: PrismaService,
		private readonly jwtService: JwtService,
		private readonly configService: ConfigService
	) {}

	async validateUser(email: string, password: string): Promise<User> {
		const user = await this.prisma.user.findUnique({ where: { email } });
		if (user) {
			await verify(user.password, password);
			return user;
		}
		return null;
	}

	async login(userData: LoginDto): Promise<{
		user: { email: string; firstName: string; lastName: string; login: string };
		tokens: TokensDto & { expiresIn: number };
	}> {
		const payload = { email: userData.email };
		const accessToken = this.jwtService.sign(payload);
		const refreshToken = this.createRefreshToken(payload);
		const newUser = await this.userService.update(
			{ email: userData.email },
			{
				refreshToken
			}
		);
		const { id, createdAt, updatedAt, password, ...user } = newUser;
		const expiresIn = Date.now() + Number(this.configService.get("JWT_EXPIRES")) * 1000;
		return {
			user: user,
			tokens: {
				accessToken,
				refreshToken,
				expiresIn
			}
		};
	}

	async register(user: AuthRegisterDto): Promise<User> {
		const hashedPassword = await hash(user.password);
		const refreshToken = this.createRefreshToken({ email: user.email });

		const userData = {
			email: user.email,
			login: user.login,
			firstName: user.firstName,
			lastName: user.lastName,
			password: hashedPassword,
			role: Role.USER,
			refreshToken
		};

		const newUser = await this.userService.create(userData);

		return newUser;
	}

	async refreshTokens({ refreshToken, id }: { refreshToken: string; id: number }): Promise<{
		accessToken: string;
		refreshToken: string;
		expiresIn: number;
	}> {
		const { iat, exp, ...payload } = await this.jwtService.verify(refreshToken);
		const user = await this.userService.findByEmail(payload.email);

		if (!user) {
			throw new BadRequestException("User was not found");
		}

		if (user.refreshToken === refreshToken) {
			const accessToken = this.createAccessToken(payload);
			const newRefreshToken = this.createRefreshToken(payload);
			const expiresIn = Date.now() + Number(this.configService.get("JWT_EXPIRES")) * 1000;

			await this.userService.update(
				{ id },
				{
					refreshToken: newRefreshToken
				}
			);

			const obj = {
				accessToken,
				refreshToken: newRefreshToken,
				expiresIn
			};
			return obj;
		}

		return null;
	}

	createAccessToken(payload: { email: string }) {
		return this.jwtService.sign(payload);
	}

	createRefreshToken(payload: { email: string }) {
		return this.jwtService.sign(payload, { expiresIn: "7d" });
	}
}
