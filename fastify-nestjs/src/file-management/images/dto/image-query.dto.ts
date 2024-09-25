import { ApiPropertyOptional } from "@nestjs/swagger";
import { IsOptional, IsString } from "class-validator";

export class ImageQueryDto {
    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    w: string;

    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    q: string;

    @ApiPropertyOptional()
    @IsString()
    @IsOptional()
    thumbnail: string;
}