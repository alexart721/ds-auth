import express from 'express';
import auth from './controllers/auth';

const router = express.Router();

router.post('/login', auth.login);
router.get('/logout', auth.logout);
router.post('/checkAccess', auth.checkToken);
router.post('/register', auth.register);
router.post('/registerToken', auth.generateRegisterToken);

export default router;
