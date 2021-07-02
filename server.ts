import http from 'http';
import express, { Response, Request } from 'express';
import cors from 'cors';
import router from './router';
import bootRedis from './redisDb';

const bootServer = (PORT: number): http.Server => {

  const app = express();
  app.locals.redisClient = bootRedis(process.env.REDIS_URL as string);

  app.use(cors());
  app.use(express.json());
  app.use(router);

  app.use((req: Request, res: Response) => {
    console.log(`Request made to ${req.url}`);
    res.status(404).send(`Page not found on auth [${req.url}]`);
  });

  const server = http.createServer(app);

  server.listen(PORT, () => {
    console.log(`Server listening at port ${PORT}`);
  });

  return server;
};

export default bootServer;
