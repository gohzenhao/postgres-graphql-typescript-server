import { UserResolver } from './resolvers/user';
import 'reflect-metadata';
import { MikroORM } from '@mikro-orm/core';
import { __prod__ } from './constants';
import mikroConfig from './mikro-orm.config';
import express from 'express';
import { ApolloServer } from 'apollo-server-express';
import { buildSchema } from 'type-graphql';
import { HelloResolver } from './resolvers/hello';
import { PostResolver } from './resolvers/post';
import { createClient } from 'redis';
import session from 'express-session';
import cors from 'cors';

// import connectRedis from 'connect-redis';


//Declaration merging - Adding your own field
declare module "express-session" {
    interface Session {
      userId: number;
    }
  }

const main = async () => {
    const orm = await MikroORM.init(mikroConfig);
    await orm.getMigrator().up();
    
    const app = express();

    app.use(cors());

    let RedisStore = require('connect-redis')(session)
    let redisClient = createClient({
        legacyMode: true
    })
    
    await redisClient.connect();

    app.use(
        session({
            name: 'qid',
            store: new RedisStore({ 
                client: redisClient,
                disableTouch: true
            }),
            cookie: {
                maxAge: 1000 * 60 * 60 * 24 * 365 * 10, // 10 years
                secure: true,
                httpOnly: true,
                sameSite: 'none'
            },
            secret: "test123123",
            resave: false,
            saveUninitialized: false,
        })
    )

    const apolloServer = new ApolloServer({
        schema: await buildSchema({
            resolvers: [HelloResolver, PostResolver, UserResolver],
            validate: false
        }),
        context: ({ req, res }) => ({em: orm.em, req, res})
    });

    await apolloServer.start();

    apolloServer.applyMiddleware({ app });

    app.listen(5000, () => {
        console.log('server started on port 5000');
    })
};

main();