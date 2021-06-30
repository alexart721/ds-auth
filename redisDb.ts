import redis, { RedisClient } from 'redis';

const bootRedis = (redisUrl: string): RedisClient => {
  const redisClient = redis.createClient(redisUrl);

  redisClient.on('error', (err) => {
    console.log(`Error connecting to Redis database: ${err}`);
  });
  redisClient.on('connect', () => {
    console.log(`Successfully connected to Redis database at ${redisUrl}`);
  });

  return redisClient;
};

export default bootRedis;
