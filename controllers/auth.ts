import { Request, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import Users from '../models/user';
import { RedisError } from 'redis';

const { SECRET_KEY } = process.env;

const login = async (req: Request, res: Response): Promise<void> => {
  const { email, password } = req.body;
  try {
    if (!email || !password) {
      res.status(400).send({message: 'Missing username or password'});
    } else {
      const user = await Users.findOne({ email }).exec();
      if (!user || !bcrypt.compareSync(password, user.password)) {
        res.status(401).send({message: 'Invalid username or password'});
      } else if (user.status === 'Banned') {
        res.status(403).send({message: 'You need to re-register'});
      } else {
        const token = jwt.sign({_id: user._id, roles: user.roles}, SECRET_KEY as string, {expiresIn: '3h'});
        res.status(200).send({accessToken: token});
      }
    }
  } catch (e) {
    res.status(500).send({message: 'Internal error'});
  }
};

// Logout a user
const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    if (!req.headers['authorization']) {
      res.status(400).send({message: 'Missing Authorization header'});
    } else {
      const token = req.headers['authorization'].split(' ')[1];
      const { exp } = jwt.verify(token, SECRET_KEY as string) as JwtPayload;
      const timeToExpire = exp || 0 - Math.floor(Date.now() / 1000);
      if (timeToExpire > 0) {
        req.app.locals.redisClient.setex(`blacklist_${token}`, timeToExpire, 'true');
        res.status(200).send({message: 'Success'});
      } else {
        res.status(200).send({message: 'Success'});
      }
    }
  } catch (e) {
    res.status(500).send({message: 'Error logging out'});
  }
};

// Register a user's password
const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;
    const user = await Users.findOne({ where: { email } });
    if (user?.status === 'Approved') {
      try {
        if (password === '') throw new Error();
        const hashPassword = await bcrypt.hash(password, 10);
        const updatedUser = await Users.findByIdAndUpdate(user?._id, { password: hashPassword, status: 'Registered' }, { new: true });
        if (SECRET_KEY) {
          const accessToken = jwt.sign({ _id: updatedUser?._id, roles: updatedUser?.roles }, SECRET_KEY, { expiresIn: '1h' });
          res.status(200).send({ accessToken });
        } else {
          throw new Error('Unable to register user');
        }
      } catch (error) {
        res.status(500).send({ error, message: 'Could not register user' });
      }
    } else {
      res.status(401).send({ message: 'User account not yet approved' });
    }
  } catch (e) {
    res.status(500).send({message: 'Internal error'});
  }
};

const checkToken = async (req: Request, res: Response): Promise<void> => {
  const { roles } = req.body;
  if (!req.headers['authorization']) {
    res.status(400).send({message: 'Missing authorization header'});
  } else {
    const token = req.headers['authorization'].split(' ')[1];
    req.app.locals.redisClient.get(`blacklist_${token}`, async (err: RedisError, data: string) => {
      if (err) {
        res.status(500).send({message: 'Internal error'});
      } else if (data) {
        res.status(401).send({message: 'You need to log in again'});
      } else {
        let _id;
        try {
          _id = (jwt.verify(token, SECRET_KEY as string) as JwtPayload)._id;
        } catch (e) {
          if (e.message === 'invalid token') {
            res.status(400).send({message: 'Invalid token'});
            return;
          }
          res.status(401).send({message: 'Unauthorized'});
          return;
        }
        
        const user = await Users.findById(_id).exec();
        switch (roles) {
          case 'Admin':
            if (user?.roles === 'Admin') {
              res.status(200).send({message: 'Approved'});
            } else {
              res.status(401).send({message: 'Invalid token for access'});
            }
          break;
          case 'User':
            if (user?.roles === 'User' || user?.roles === 'Admin') {
              res.status(200).send({message: 'Approved'});
            } else {
              res.status(401).send({message: 'Invalid token for access'});
            }
          break;
          default:
            res.status(400).send({message: 'Invalid role'});
        }
      } 
    });
  }
};

export default {
  login, logout, register, checkToken
};
