const {prisma} = require('../prisma/prisma-client');
const brypt = require('bcrypt');
const jwt = require('jsonwebtoken')

const login = async(req, res) => {
    const {email, password} = req.body

    if (!email || !password) {
        return res.status(400).json({message: 'Пожалуйста, заполните обязательные поля!'})
    }

    const user = await prisma.user.findFirst({
        where: {
            email,
        }
    })

    const isPasswordCorrect = user && (await brypt.compare(password, user.password));

    if(user && isPasswordCorrect) {
        res.status(200).json({
            id: user.id,
            email: user.email,
            name: user.name
        })
    } else {
        return res.status(400).json({message: 'Неверно веден логин или пароль!'})
    }
}

const register = async(req, res) => {
    const {email, password, name} = req.body;

    if(!email || !password || !name) {
        return res.status(400).json({message: 'Пожалуйста, заполните обязательные поля!'})
    }

    const registeredUser = await prisma.user.findFirst({
        where: {
            email
        }
    });

    if(registeredUser) {
        return res.status(400).json({message: 'Пользователь  с таким email уже существует'})
    }

    const salt = await brypt.genSalt(10);
    const hashedPassword = await brypt.hash(password, salt);

    const user = await prisma.user.create({
        data: {
            email,
            name,
            password: hashedPassword
        }
    });

    const secret = process.env.JWT_SECRET;

    if(user && secret) {
        res.status(201).json({
            id: user.id,
            email: user.email,
            name,
            token: jwt.sign({id: user.id}, secret, {expiresIn: '30d'})
        })
    } else {
        return res.status(400).json({message: 'Не удалось создать пользователя'})
    }
}

const current = async(req, res) => {
    res.send('current');
}

module.exports = {
    login, 
    register,
    current
}