import { Injectable, NotFoundException, Res } from '@nestjs/common';
import { CreateImageDto } from './dto/create-image.dto';
import { UpdateImageDto } from './dto/update-image.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Image } from './entities/image.entity';
import { Brackets, In, Repository } from 'typeorm';
import path from 'path';
import fs from 'fs';
import sharp from 'sharp';
import { ImageQueryDto } from './dto/image-query.dto';
import { AccountsService } from 'src/auth-system/accounts/accounts.service';
import { AuthUser, Role } from 'src/common/types/global.type';
import { getImageMetadata } from 'src/utils/getImageMetadata';
import { QueryDto } from 'src/common/dto/query.dto';
import { applySelectColumns } from 'src/utils/apply-select-cols';
import { imageSelectColumns } from './helpers/image-select-cols';
import paginatedData from 'src/utils/paginatedData';
import { FastifyReply } from 'fastify';

@Injectable()
export class ImagesService {
  constructor(
    @InjectRepository(Image) private imagesRepository: Repository<Image>,
    private readonly accountService: AccountsService
  ) { }

  async upload(createImageDto: CreateImageDto, currentUser: AuthUser) {
    const account = await this.accountService.findOne(currentUser.accountId);

    const images: { id: string, url: string }[] = [];

    for (const uploadImage of createImageDto.images) {
      const metaData = await getImageMetadata(uploadImage);

      const newImage = this.imagesRepository.create({
        ...metaData,
        name: createImageDto.name || metaData.originalName,
        uploadedBy: account
      })

      await this.imagesRepository.save(newImage);

      images.push({
        id: newImage.id,
        url: newImage.url
      });
    }

    return {
      message: 'Image(s) Uploaded',
      images,
      count: createImageDto.images.length,
    }
  }

  async findAll(queryDto: QueryDto, currentUser: AuthUser) {
    const queryBuilder = this.imagesRepository.createQueryBuilder('image');

    queryBuilder
      .orderBy('image.createdAt', 'DESC')
      .skip(queryDto.skipPagination === 'true' ? undefined : queryDto.skip)
      .take(queryDto.skipPagination === 'true' ? undefined : queryDto.take)
      .leftJoin('image.uploadedBy', 'uploadedBy')
      .where(new Brackets(qb => {
        currentUser.role !== Role.ADMIN && qb.where({ uploadedBy: { id: currentUser.accountId } })
      }))

    applySelectColumns(queryBuilder, imageSelectColumns, 'image');

    return paginatedData(queryDto, queryBuilder);
  }

  async findAllByIds(ids: string[]) {
    return await this.imagesRepository.find({
      where: {
        id: In(ids)
      }
    })
  }

  async findOne(id: string, currentUser?: AuthUser) {
    const existingImage = await this.imagesRepository.findOne({
      where: {
        id,
        uploadedBy: {
          id: currentUser?.accountId
        }
      },
    });
    if (!existingImage) throw new NotFoundException('Image not found');

    return existingImage
  }

  async serveImage(filename: string, queryDto: ImageQueryDto, @Res() res: FastifyReply) {
    const imagePath = path.join(process.cwd(), 'public', filename);

    if (queryDto.thumbnail === 'true') {
      const thumbnailPath = path.join(process.cwd(), 'public', filename.replace(/(\.[\w\d_-]+)$/i, '-thumbnail.webp'));

      try {
        const thumbnailBuffer = await sharp(fs.readFileSync(thumbnailPath)).toBuffer();
        res.header('Content-Type', 'image/webp');
        res.send(thumbnailBuffer);
        return;
      } catch (err) {
        console.error('Thumbnail not found:', err);
        res.status(404).send('Thumbnail not found');
        return;
      }
    }

    try {
      const originalImage = fs.readFileSync(imagePath);

      const resizedImageBuffer = await sharp(originalImage)
        .webp({ quality: isNaN(Number(queryDto.q)) ? 90 : parseInt(queryDto.q) })
        .resize(isNaN(Number(queryDto.w)) ? undefined : parseInt(queryDto.w))
        .toBuffer();

      res.header('Content-Type', 'image/webp');
      res.send(resizedImageBuffer);
    } catch (err) {
      console.error('Original image not found:', err);
      res.status(404).send('Original image not found');
    }
  }

  async update(id: string, updateImageDto: UpdateImageDto, currentUser: AuthUser) {
    const existing = await this.findOne(id, currentUser?.role !== 'admin' ? currentUser : undefined);

    // update image name only
    existing.name = updateImageDto.name;

    const savedImage = await this.imagesRepository.save(existing);

    return {
      message: 'Image updated',
      image: {
        url: savedImage.url,
        id: savedImage.id
      }
    }
  }

  async remove(id: string, currentUser: AuthUser) {
    const existing = await this.findOne(id, currentUser);
    await this.imagesRepository.remove(existing);
    return {
      message: 'Image deleted successfully'
    }
  }
}
