import { ApiProperty, OmitType } from "@nestjs/swagger";
import { IsNotEmpty, IsOptional, IsString } from "class-validator";
import { HasMimeType, IsFile, MaxFileSize, MemoryStoredFile } from "nestjs-form-data";

export class CreateImageDto {
    @ApiProperty({ type: [String], format: 'binary', description: 'Image' })
    @HasMimeType(['image/png', 'image/jpg', 'image/jpeg', 'image/webp'], { each: true })
    @IsFile({ each: true })
    @MaxFileSize(5 * 1024 * 1024, { each: true })
    @IsNotEmpty({ each: true })
    images: MemoryStoredFile[]

    @ApiProperty()
    @IsString()
    @IsOptional()
    name?: string
}
