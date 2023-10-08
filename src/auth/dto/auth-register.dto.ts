import { IsEmail, IsString, MaxLength, MinLength } from "class-validator";

export class AuthRegisterDto {
	@IsEmail()
	email: string;

	@IsString()
	@MaxLength(16)
	login: string;

	@IsString()
	firstName: string;

	@IsString()
	lastName: string;

	@IsString()
	@MinLength(8)
	password: string;
}
