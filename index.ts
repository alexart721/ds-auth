import bootDb from './db';
import bootServer from './server';

const PORT = Number(process.env.PORT);
const url = String(process.env.DB_BASE_URL);
const DB_NAME = String(process.env.DB_NAME);

bootDb(url, DB_NAME);
bootServer(PORT);
