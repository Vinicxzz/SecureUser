require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// Definindo o modelo de usuário
const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

// Função de Middleware para Verificação do Token
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ msg: 'Acesso negado!' });
    }

    try {
        const secret = process.env.JWT_SECRET;
        jwt.verify(token, secret, (err, user) => {
            if (err) {
                return res.status(403).json({ msg: 'Token inválido!' });
            }
            req.user = user;
            next();
        });
    } catch (err) {
        res.status(500).json({ msg: 'Erro no servidor!' });
    }
}

// Rota Privada
app.get("/user/:id", checkToken, async (req, res) => {
    const { id } = req.params;

    try {
        const user = await User.findById(id).select('-password');

        if (!user) {
            return res.status(404).json({ msg: 'Usuário não encontrado' });
        }

        res.status(200).json(user);
    } catch (err) {
        console.log(err);
        res.status(500).json({ msg: 'Erro no servidor! Por favor, tente novamente.' });
    }
});

// Rota Pública
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Success!' });
});

// Rota de Registro de Usuário
app.post('/auth/register', async (req, res) => {
    const { name, email, password, passwordconfirm } = req.body;

    if (!name) return res.status(422).json({ message: 'Name is required' });
    if (!email) return res.status(422).json({ message: 'Email is required' });
    if (!password) return res.status(422).json({ message: 'Password is required' });
    if (password !== passwordconfirm) return res.status(422).json({ message: 'Passwords do not match' });

    const userExist = await User.findOne({ email: email });
    if (userExist) return res.status(422).json({ message: 'Email already exists' });

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({ name, email, password: passwordHash });

    try {
        await user.save();
        res.status(201).json({ msg: 'User created successfully!' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server error, please try again' });
    }
});

// Rota de Login
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email) return res.status(422).json({ message: 'Email is required' });
    if (!password) return res.status(422).json({ message: 'Password is required' });

    try {
        const user = await User.findOne({ email: email });
        if (!user) return res.status(404).json({ message: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ msg: "Autenticação com sucesso!", token: token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ msg: 'Server error, please try again' });
    }
});

// Credenciais do banco de dados
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
    .connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.z31pf08.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`)
    .then(() => {
        app.listen(3030, () => {
            console.log('Connected to the database and server is running on port 3030');
        });
    })
    .catch((err) => console.log(err));