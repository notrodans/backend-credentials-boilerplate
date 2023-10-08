import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";

async function bootstrap() {
	const app = await NestFactory.create(AppModule);
	app.enableCors({ credentials: true, origin: process.env.WEBSITE_URL });
	app.setGlobalPrefix("/api");
	await app.listen(process.env.PORT || 3000);
}
bootstrap();
