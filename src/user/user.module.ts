import { Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { JwtModule } from "@nestjs/jwt";
import { JwtStrategy } from "../auth/strategies/jwt.strategy";
import { getJwtConfig } from "../config/getJwtConfig";
import { UserController } from "./user.controller";
import { UserService } from "./user.service";

@Module({
	imports: [
		JwtModule.registerAsync({
			imports: [ConfigModule],
			inject: [ConfigService],
			useFactory: getJwtConfig
		})
	],
	controllers: [UserController],
	providers: [UserService, JwtStrategy, ConfigService],
	exports: [UserService]
})
export class UserModule {}
