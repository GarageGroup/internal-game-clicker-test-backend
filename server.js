const express = require('express');
const crypto = require('crypto'); // инструмент для работы с хэшами (нам нужен для формировани токена)
const dotenv = require('dotenv'); // модуль для получения переменных с окружения проекта (глобальная переменная)
const cors = require('cors');

dotenv.config();

const app = express();

app.use(cors({
    origin: '*',
}));

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    next();
})

// app.use(cors({ origin: '*' }));
app.use(express.json());

const KEY = process.env.SECRET_KEY;
const PORT = process.env.PORT;
const BOT_TOKEN = process.env.BOT_TOKEN

//Синхронизация 
app.post('/sync', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(401).json({ error: 'The token is missing, access is prohibited!' });
    }

    return res.status(200).json({ status: 200, message: 'Synchronization with the database was successful!' });
});

// Генерация токена 
app.post('/generateToken', (req, res) => {
    const { data } = req.body;

    if (!data) {
        return res.status(422).json({ error: 'Data is missing!' })
    }
    /* 
    Для проверки валидности, нужно получить отформотировать все данные без hash и сформировать с этими данными + bot token свой хэш и сравнить с хэшом полученным из data
    */
    try {
        const params = new URLSearchParams(data); // стринг значение делаем в объект key: value
        const hash = params.get('hash');
        params.delete('hash');

        /*
         тут ключ значение делаем массивами и потом переводим в текстовый формат и сортируем и добавляем разделитель между ними
         Это формат ТГ, key=value\n
        */
        const checkString = [...params]
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

        const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
        /*
        мы сначала создаем hmac, где ключом является WebAppData, и обновляем  мы hmac данными BOT_TOKEN
        А потому этот hmac используем для создания хэша 
        Сделано так ради безопасности данных 
        */
        const validHash = crypto.createHmac('sha256', secretKey).update(checkString).digest('hex');

        if (validHash != hash) {
            return res.status(403).json({ error: 'Invalid initData signature!' });
        }

        console.log("date:", new Date());
        
        const tgID = JSON.parse(params.get('user')).id;
        const unixtime = Math.floor(Date.now() / 1000);
        const dataHash = `${tgID}${KEY}${unixtime}`;
        const token = crypto.createHash('sha256').update(dataHash).digest('hex');
        return res.json({ token });
    }
    catch (error) {
        return res.status(400).json({ error: 'Invalid data format!' });
    }
});

app.listen(PORT, () => {
    console.log(`The server is running on http://localhost:${PORT}`);
});