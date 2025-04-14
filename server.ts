import express, { Request, Response, NextFunction } from 'express';

/*Express — это  фреймворк для Node.js, которая упрощает, систематизирует и структурирует процесс создания сервера. 
Она предоставляет удобные инструмент для работы с HTTP-запросами, маршрутизацией и другими аспектами веб-сервера. 
Без Express пришлось бы использовать встроенный модуль Node.js http и писать гораздо больше кода для обработки запросов, маршрутов и других задач. 
*/

import crypto from 'crypto'; // инструмент для работы с хэшами (нам нужен для формировани токена)
import jwt from 'jsonwebtoken'; // инструмент для формирования и проверки валидности JWT-токена
import dotenv from 'dotenv'; // модуль для получения переменных с окружения проекта (глобальная переменная)
import cors from 'cors';

import { SyncRequestBody, GenerateTokenRequestBody, BalanceRequestBody } from './state-model'
import { randomUUID } from 'crypto';

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
const SECRET_KEY_KASSA = process.env.SECRET_KEY_KASSA;
const ID_KASSA_SHOP = process.env.ID_KASSA_SHOP;
const URL_KASSA = process.env.URL_KASSA || '';

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

// app.post('/syncTestOne', (req: Request, res: any) => {
//     const body: SyncRequestBody = req.body;

//     if (!body.token) {
//         return res.status(401).json({ error: 'The token is missing, access is prohibited!' });
//     }

//     setTimeout(() => {
//         return res.status(200).json({ status: 200, message: 'All good! Test one passed!' });
//     }, 5000)
// });

// app.post('/syncTestTwo', (req: Request, res: any) => {
//     const body: SyncRequestBody = req.body;

//     if (!body.token) {
//         return res.status(401).json({ error: 'The token is missing, access is prohibited!' });
//     }

//     setTimeout(() => {
//         return res.status(200).json({ status: 200, message: 'Test two executed successfully!' });
//     }, 5000)
// });

app.post('/generateToken', (req: Request, res: any) => {
    console.log('Я запустился!');
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

app.post('/payment', (req: Request, res: any) => {
    console.log('Payment started in server');
    const body: BalanceRequestBody = req.body;
    console.log('Payment started', body.data.amountBalance);

    const idempotenceKey = randomUUID();
    const credentials = `${ID_KASSA_SHOP}:${SECRET_KEY_KASSA}`;
    const encodedCredentials = Buffer.from(credentials).toString('base64');

    const requestHeader = {
        "Authorization": `Basic ${encodedCredentials}`,
        "Content-Type": "application/json",
        "Idempotence-Key": idempotenceKey,
    };

    const requestBody =
    {
        "amount": {
            "value": body.data.amountBalance,
            "currency": "RUB"
        },
        "confirmation": {
            "type": "redirect",
            "return_url": "https://example.com/return-url"
        },
        "capture": true,
        "description": body.data.type
    };


    // if (!body.token) {
    //     return res.status(401).json({ error: 'The token is missing, access is prohibited!' });
    // }

    try {
        fetch(URL_KASSA, {
            method: 'POST',
            headers: requestHeader,
            body: JSON.stringify(requestBody)
        })
            .then((response: any) => {
                return response.json();
            })
            .then((data: any) => {
                console.log(data.confirmation.confirmation_url);
                return res.status(200).json({
                    status: 200,
                    confirmationUrl: data.confirmation.confirmation_url
                });
            })
            .catch((error) => {
                return res.status(404).json({ error: error.message });
            })
    }
    catch (error) {
        return res.status(500).json({ error: 'Invalid server' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});