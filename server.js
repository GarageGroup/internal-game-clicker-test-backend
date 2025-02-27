"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const crypto_1 = __importDefault(require("crypto")); // инструмент для работы с хэшами (нам нужен для формировани токена)
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken")); // инструмент для формирования и проверки валидности JWT-токена
const dotenv_1 = __importDefault(require("dotenv")); // модуль для получения переменных с окружения проекта (глобальная переменная)
const cors_1 = __importDefault(require("cors"));
dotenv_1.default.config(); // вызов, который загружает все переменные из env в process.env
const app = (0, express_1.default)(); // создаем приложение, по сути то благодаря чему работает сервер
app.use((0, cors_1.default)({ origin: '*' }));
app.use(express_1.default.json());
app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
    next();
});
// Глобальные переменные
const KEY = process.env.SECRET_KEY || '';
const PORT = process.env.PORT;
const BOT_TOKEN = process.env.BOT_TOKEN || '';
// Routes
app.post('/sync', (req, res) => {
    const body = req.body;
    if (!body.token) {
        return res.status(401).json({ error: 'The token is missing, access is prohibited!' });
    }
    try {
        jsonwebtoken_1.default.verify(body.token, KEY); // функция для проверки валидности токена по ключу, если ошибка, то 401 (идет в catch)
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
app.post('/generateToken', (req, res) => {
    console.log('Я запустился!');
    const body = req.body;
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
        const secretKey = crypto_1.default
            .createHmac('sha256', 'WebAppData')
            .update(BOT_TOKEN)
            .digest();
        /*
        мы сначала создаем hmac, где ключом является WebAppData, и обновляем  мы hmac данными BOT_TOKEN
        А потому этот hmac используем для создания хэша
        Сделано так ради безопасности данных
        */
        const validHash = crypto_1.default
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
        const token = jsonwebtoken_1.default.sign({ id: tgID }, KEY); // функция для формирования токена JWT (включает себя tgID и подписывается ключом)
        return res.json({ token });
    }
    catch (error) {
        console.error('Error:', error);
        return res.status(400).json({ error: 'Invalid data format!' });
    }
});
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
