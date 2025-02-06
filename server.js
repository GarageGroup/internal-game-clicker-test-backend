const express = require('express');
const app = express();
const port = 5000;

app.get('/', (req, res) => {
  res.send('Сервер работает! 🚀');
});

app.listen(port, () => {
  console.log(`Сервер запущен на http://localhost:${port}`);
});