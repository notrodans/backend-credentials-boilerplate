import { Injectable, UnauthorizedException } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { PassportStrategy } from "@nestjs/passport";
import { User } from "@prisma/client";
import { Strategy, ExtractJwt } from "passport-jwt";
import { PrismaService } from "../../database/prisma.service";
import { JwtPayload } from "../../types/jwt-payload";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
	constructor(
		private readonly prisma: PrismaService,
		private readonly configService: ConfigService
	) {
		super({
			jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
			ignoreExpiration: false,
			secretOrKey: configService.get("JWT_SECRET")
		});
	}

	async validate(payload: JwtPayload): Promise<User> {
		const user = await this.prisma.user.findUnique({ where: { email: payload.email } });
		if (!user) {
			throw new UnauthorizedException();
		}
		return user;
	}
}
