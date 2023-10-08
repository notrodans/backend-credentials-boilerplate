import { Module } from "@nestjs/common";
import { ConfigModule } from "@nestjs/config";
import { AuthModule } from "./auth/auth.module";
import { PrismaModule } from "./database/prisma.module";
import { UserModule } from "./user/user.module";

@Module({
	imports: [ConfigModule.forRoot(), PrismaModule, AuthModule, UserModule]
})
export class AppModule {}
