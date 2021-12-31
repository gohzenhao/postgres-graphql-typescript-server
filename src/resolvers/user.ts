import { session } from 'express-session';
import { User } from './../entities/User';
import { MyContext } from './../types';
import { Resolver, Query, Mutation, InputType, Field, Arg, Ctx, ObjectType } from 'type-graphql';
import argon2 from 'argon2';

@InputType()
class UsernamePasswordInput {
    @Field()
    username: string

    @Field()
    password: string
}

@ObjectType()
class FieldError {
    @Field()
    field: string;

    @Field()
    message: string;
}

@ObjectType()
class UserResponse {
    @Field(() => [FieldError], { nullable: true })
    errors?: FieldError[]

    @Field(() => User, { nullable: true })
    user?: User
}

@Resolver()
export class UserResolver {


    @Query(() => User, { nullable: true})
    async me(
        @Ctx() { em, req }: MyContext
    ) {
        if(!req.session.userId) {
            return null;
        }
        
        const user = await em.findOne(User, {id: req.session.userId});
        return user;
    }

    @Mutation(() => User)
    async register(
        @Arg('options') options: UsernamePasswordInput,
        @Ctx() { em, req }: MyContext
    ) {
        const hashedPassword = await argon2.hash(options.password);
        const user = em.create(User, { username: options.username, password: hashedPassword });
        await em.persistAndFlush(user);

        req.session.userId = user.id;
        
        return user;
    }

    @Mutation(() => UserResponse)
    async login(
        @Arg('options') options: UsernamePasswordInput,
        @Ctx() { em, req }: MyContext
    ): Promise<UserResponse> {
        const user = await em.findOne(User, { username: options.username });
        if(!user) {
            return {
                errors: [
                    {
                        field: 'username',
                        message: 'Username does not exist'
                    }
                ]
            };
        }

        const valid = await argon2.verify(user.password, options.password);
        if(!valid) {
            return {
                errors: [
                    {
                        field: 'password',
                        message: 'Incorrect password'
                    }
                ]
            };
        }

        req.session.userId = user.id;

        return {
            user
        };
    }


}