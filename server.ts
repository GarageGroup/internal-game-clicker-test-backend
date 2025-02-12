import express, { Request, Response, NextFunction } from 'express';
import crypto from 'crypto'; // инструмент для работы с хэшами (нам нужен для формировани токена)
import jwt from 'jsonwebtoken'; // инструмент для формирования и проверки валидности JWT-токена
import dotenv from 'dotenv'; // модуль для получения переменных с окружения проекта (глобальная переменная)
import cors from 'cors';

import { SyncRequestBody, GenerateTokenRequestBody } from './state-model'

dotenv.config(); // вызов, который загружает все переменные из env в process.env

const app = express(); // создаем приложение, по сути то благодаря чему работает сервер
app.use(cors({ origin: '*' }));
app.use(express.json());

app.use((req: Request, res: Response, next: NextFunction) => { //то способ перейти к следующему шагу в обработке запроса. Нужно, чтобы сервер знал, когда перейти к следующему обработчику и, например, завершить проверку или обработку данных.
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    next();
});

// Глобальные переменные
const KEY = process.env.SECRET_KEY || '';
const PORT = process.env.PORT;
const BOT_TOKEN = process.env.BOT_TOKEN || '';

// Routes
app.post('/sync', (req: Request, res: any) => {
    const body: SyncRequestBody = req.body;

    if (!body.token) {
        return res.status(401).json({ error: 'The token is missing, access is prohibited!' });
    }

    try {
        jwt.verify(body.token, KEY); // функция для проверки валидности токена по ключу, если ошибка, то 401 (идет в catch)
        return res.status(200).json({ status: 200, message: 'Synchronization successful!' });
    }

    catch (error) {
        return res.status(401).json({ error: 'Invalid token!' });
    }
});

app.post('/generateToken', (req: Request, res: any) => {
    const body: GenerateTokenRequestBody = req.body;

    if (!body.data) {
        return res.status(422).json({ error: 'Data is missing!' });
    }

    /* 
    Для проверки валидности, нужно получить отформотировать все данные без hash и сформировать с этими данными + bot token свой хэш и сравнить с хэшом полученным из data
    */
    try {
        const params = new URLSearchParams(body.data); // стринг значение делаем в объект key: value
        const hash = params.get('hash');
        params.delete('hash');

        /*
         тут ключ значение делаем массивами и потом переводим в текстовый формат и сортируем и добавляем разделитель между ними
         Это формат ТГ, key=value\n
        */

        const checkString = Array.from(params.entries())
            .map(([key, value]) => `${key}=${value}`)
            .sort()
            .join('\n');

        /* 
        createHmac/createHash - это формирует хэш;
        отличие между HMAC & Hash:
        HMAC — код аутентификации сообщения, который обеспечивает проверку целостности и подлинности данных.
        Для вычисления HMAC используется секретный ключ

        createHash - обычный хэш, создается только на основе данных, без использования ключа

        sha256 - вид хэширования
        в createHmac BOT_TOKEN прописывается для того, чтобы указать ключ для хэширования
        update('data') - то что мы хэшируем
        digest - метод для вывода результата, где hex - это формат вывода
        */

        const secretKey = crypto
            .createHmac('sha256', 'WebAppData')
            .update(BOT_TOKEN)
            .digest();

        /*
        мы сначала создаем hmac, где ключом является WebAppData, и обновляем  мы hmac данными BOT_TOKEN
        А потому этот hmac используем для создания хэша 
        Сделано так ради безопасности данных 
        */

        const validHash = crypto
            .createHmac('sha256', secretKey)
            .update(checkString)
            .digest('hex');

        if (validHash != hash) {
            return res.status(403).json({ error: 'Invalid initData signature!' });
        }

        const user = params.get('user');

        if (!user) {
            return res.status(400).json({ error: 'User data not found' });
        }

        const tgID = JSON.parse(user).id;
        const token = jwt.sign({ id: tgID }, KEY); // функция для формирования токена JWT (включает себя tgID и подписывается ключом)

        return res.json({ token });

    } catch (error) {
        console.error('Error:', error);
        return res.status(400).json({ error: 'Invalid data format!' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});