import { BadRequestException, Inject, Injectable, InternalServerErrorException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Brackets, DataSource } from 'typeorm';
import { REQUEST } from '@nestjs/core';
import { BaseRepository } from 'src/common/repository/base-repository';
import { FastifyRequest } from 'fastify';
import { UsersQueryDto } from './dto/user-query.dto';
import paginatedData from 'src/utils/paginatedData';
import { User } from './entities/user.entity';
import { applySelectColumns } from 'src/utils/apply-select-cols';
import { userSelectCols } from './helpers/user-select-cols';

@Injectable()
export class UsersService extends BaseRepository {
  constructor(
    private readonly datasource: DataSource,
    @Inject(REQUEST) req: FastifyRequest,
  ) { super(datasource, req) }

  private readonly usersRepo = this.datasource.getRepository<User>(User);

  async findAll(queryDto: UsersQueryDto) {
    const queryBuilder = this.usersRepo.createQueryBuilder('user');

    queryBuilder
      .orderBy("user.createdAt", queryDto.order)
      .skip(queryDto.skip)
      .take(queryDto.take)
      .withDeleted()
      .leftJoin("user.account", "account")
      .leftJoin("user.profileImage", "profileImage")
      .andWhere(new Brackets(qb => {
        queryDto.role && qb.andWhere('account.role = :role', { role: queryDto.role });
      }))

    applySelectColumns(queryBuilder, userSelectCols, 'user');

    return paginatedData(queryDto, queryBuilder);
  }

  async findOne(id: string) {
    const existing = await this.usersRepo.findOne({
      where: { id },
      select: userSelectCols,
    })
    if (!existing) throw new BadRequestException('User not found');

    return existing;
  }

  async update(updateUserDto: UpdateUserDto) {
    // const existingUser = await this.findOne(currentUser.userId);
    // const existingAccount = await this.accountRepo.findOneBy({ id: currentUser.accountId });
    // if (!existingAccount) throw new InternalServerErrorException('Unable to update the associated profile. Please contact support.');

    // const profileImage = ((updateUserDto.profileImageId && existingUser.profileImage?.id !== updateUserDto.profileImageId) || !existingUser.profileImage)
    //   ? await this.imagesService.findOne(updateUserDto.profileImageId)
    //   : existingUser.profileImage;

    // // update user
    // Object.assign(existingUser, {
    //   ...updateUserDto,
    // });

    // // assign profile image
    // existingUser.profileImage = profileImage;

    // await this.usersRepo.save(existingUser);

    // Object.assign(existingAccount, {
    //   firstName: updateUserDto.firstName || existingAccount.firstName,
    //   lastName: updateUserDto.lastName,
    // })

    // // await this.accountRepo.save(existingAccount);

    // return {
    //   message: 'Profile Updated'
    // }
  }

  async remove(id: string) {
    const existingUser = await this.findOne(id);
    await this.usersRepo.softRemove(existingUser);

    return {
      message: 'User removed',
    }
  }
}
