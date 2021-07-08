import { connect, Mongoose } from 'mongoose';

const bootDb = async (url: string, DB_NAME: string): Promise<Mongoose | undefined> => {
  console.log(url);
  try {
    const connection = await connect(url, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      useFindAndModify: false,
    });
    console.log(`Successfully connected to the ${DB_NAME} ...`);
    return connection;
  } catch (error) {
    console.log(error);
  }
};

export default bootDb;
