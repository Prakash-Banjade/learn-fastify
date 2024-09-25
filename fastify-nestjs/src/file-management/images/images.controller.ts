import { Controller, Get, Post, Body, Patch, Param, Delete, Query, Res } from '@nestjs/common';
import { ImagesService } from './images.service';
import { CreateImageDto } from './dto/create-image.dto';
import { UpdateImageDto } from './dto/update-image.dto';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { FormDataRequest } from 'nestjs-form-data';
import { Response } from 'express';
import { SkipThrottle, Throttle } from '@nestjs/throttler';
import { ImageQueryDto } from './dto/image-query.dto';
import { AuthUser } from 'src/common/types/global.type';
import { CurrentUser } from 'src/common/decorators/user.decorator';
import { QueryDto } from 'src/common/dto/query.dto';
import { Public } from 'src/common/decorators/setPublicRoute.decorator';

@ApiBearerAuth()
@ApiTags('Upload Images')
@Controller('images') // route-path: /upload/images
export class ImagesController {
  constructor(private readonly imagesService: ImagesService) { }

  @Post()
  @FormDataRequest()
  upload(@Body() createImageDto: CreateImageDto, @CurrentUser() currentUser: AuthUser) {
    return this.imagesService.upload(createImageDto, currentUser);
  }

  @Get()
  findAll(@Query() queryDto: QueryDto, @CurrentUser() currentUser: AuthUser) {
    return this.imagesService.findAll(queryDto, currentUser);
  }

  @Public()
  @Get('get-image/:slug')
  @SkipThrottle()
  getImage(@Param("slug") slug: string, @Query() queryDto: ImageQueryDto, @Res() res: Response, @CurrentUser() currentUser?: AuthUser) {
    return this.imagesService.serveImage(slug, queryDto, res);
  }

  // @Get(':id')
  // findOne(@Param('id') id: string, @Res() res: Response) {
  //   return this.imagesService.findOne(id);
  // }

  @Patch(':id')
  @FormDataRequest()
  update(@Param('id') id: string, @Body() updateImageDto: UpdateImageDto, @CurrentUser() currentUser: AuthUser) {
    return this.imagesService.update(id, updateImageDto, currentUser);
  }

  @Delete(':id')
  remove(@Param('id') id: string, @CurrentUser() currentUser: AuthUser) {
    return this.imagesService.remove(id, currentUser);
  }
}
