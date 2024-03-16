import {
	BadRequestException,
	Body,
	Controller,
	HttpCode,
	Post,
	UnauthorizedException,
	UseGuards,
	UsePipes,
	ValidationPipe
} from "@nestjs/common";
import { UserService } from "../user/user.service";
import { AuthService } from "./auth.service";
import { LoginDto } from "./dto/auth-login.dto";
import { AuthRegisterDto } from "./dto/auth-register.dto";
import { TokensDto } from "./dto/auth-token.dto";
import { JwtAuthGuard } from "./guards/auth-guard";
import { User } from "../decorators/user.decorator";
import { User as UserType } from "@prisma/client";

@Controller("auth")
export class AuthController {
	constructor(
		private readonly authService: AuthService,
		private readonly userService: UserService
	) {}

	@UsePipes(ValidationPipe)
	@Post("login")
	async login(@Body() loginDto: LoginDto): Promise<{
		user: { email: string; firstName: string; lastName: string; login: string };
		tokens: TokensDto;
	}> {
		const valid = await this.authService.validateUser(loginDto.email, loginDto.password);

		if (!valid) {
			throw new UnauthorizedException("Wrong credentials");
		}

		return await this.authService.login(loginDto);
	}

	@UsePipes(ValidationPipe)
	@HttpCode(201)
	@Post("register")
	async register(@Body() registerDto: AuthRegisterDto): Promise<void> {
		const oldUser = await this.userService.findByEmail(registerDto.email);

		if (oldUser) {
			throw new BadRequestException("User exists");
		}

		await this.authService.register(registerDto);
	}

	@UseGuards(JwtAuthGuard)
	@UsePipes(ValidationPipe)
	@Post("refresh")
	async refresh(
		@Body() { refreshToken }: Pick<TokensDto, "refreshToken">,
		@User() userInfo: UserType
	) {
		const obj = {
			refreshToken,
			id: userInfo.id
		};
		const refresh = await this.authService.refreshTokens(obj);

		if (!refresh) {
			throw new UnauthorizedException();
		}

		console.log(refresh);

		return refresh;
	}
}
