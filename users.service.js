const exp = require('constants');
const { query } = require('express');
const
    express = require('express'),
    BaseService = require('./base.manipulation.service.js'),
    passport = require('passport'),
    db = require('../database'),
    moment = require('moment'),
    passport_bearer = require('passport-http-bearer'),
    crypto = require('crypto');




function createLeveledStrategy(level) {
    return new passport_bearer(function(token, done) {
        console.log('Authenticate with token:', token);
        db.UserAuth.findOne({
                where: { token },
                include: [db.User]
            })
            .then(auth => {
                if (auth == null) {
                    done(null, null);
                } else {
                    console.log('required level', level, 'user level', auth.user.level);
                    if (auth.user.level <= level) {
                        done(null, auth.user);
                    } else {
                        done(null, null);
                    }
                }
            })
            .catch(err => {
                done(err);
            });
    });
}


new passport_bearer(function(refreshToken, done) {
    console.log(' refreshToken:', refreshToken);
    db.UserAuth.findOne({
            where: { refreshToken },
            include: [db.User]
        })
        .then(auth => {
            if (auth == null) {
                done(null, null);
            } else {


                console.log('required level', level, 'user level', auth.user.level);
                if (auth.user.level <= level) {
                    done(null, auth.user);
                } else {
                    done(null, null);
                }
            }
        })
        .catch(err => {
            done(err);
        });
})










// TODO стратегию для обновления токена, рефреш токен, 

const UserLevels = {
    admin: 0,
    moderator: 4,
    proUser: 6,
    user: 8
};

class UserService extends BaseService {
    constructor(app, ctx) {
        super(app, ctx, '/users', db.User);

        app.use(passport.initialize());

        passport.use('admin', createLeveledStrategy(UserLevels.admin));
        passport.use('moderator', createLeveledStrategy(UserLevels.moderator));
        passport.use('user', createLeveledStrategy(UserLevels.user));


        ctx.authAdmin = passport.authenticate('admin', { session: false });
        ctx.authModerator = passport.authenticate('moderator', { session: false });
        ctx.authUser = passport.authenticate('user', { session: false });
        this.ensureAdminUser();

        this.list_attributes.push('email', 'phone');
        this.setInterval();
    }

    async ensureAdminUser() {
        const usersCount = await db.User.count();
        if (usersCount === 0) {
            const passwordSalt = crypto.randomBytes(32).toString('hex');
            const passwordHash = this.hash('pass' + passwordSalt);
            await db.User.create({
                email: 'a@a.a',
                level: UserLevels.admin,
                passwordSalt,
                passwordHash,
                valid: true
            });
        }
    }
    0
    hash(string) {
        const cryptoHash = crypto.createHash('sha256');
        cryptoHash.update(string);
        return cryptoHash.digest('hex');
    }

    async login(req, resp, next) {
        let user = await db.User.findOne({
            where: {
                [db.Op.or]: {
                    email: req.body.username,
                    phone: req.body.username.replace(/\s+/g, '')
                }
            }
        });
        if (user == null) {
            console.log('no such user');
            resp.sendStatus(401);
        } else {
            const extendedPassword = req.body.password + user.passwordSalt;
            const passwordHash = this.hash(extendedPassword);
            if (user.passwordHash === passwordHash) {
                console.log('create token pair for user', user.email || user.phone);
                //user ok, crete tokens
                const userAuth = await db.UserAuth.create({
                    user_id: user.id,
                    token: crypto.randomBytes(32).toString('hex'),
                    refreshToken: crypto.randomBytes(32).toString('hex'),
                    expireAt: moment().add(15, 'minutes').toDate()
                });
                // TODO userAuth auto token
                console.log(userAuth.expireAt);
                resp.send({
                    email: user.email,
                    phone: user.phone,
                    level: user.level,
                    token: userAuth.token,
                    refreshToken: userAuth.refreshToken
                });
            } else {
                resp.sendStatus(401);
            }
        }
    }

    async logout(req, resp, next) {
        await db.UserAuth.destroy({
            where: {
                user_id: req.user.id
            }
        });
        resp.sendStatus(200);
    }

    createPasswordPair(password) {
        const passwordSalt = crypto.randomBytes(32).toString('hex');
        const passwordHash = this.hash(password + passwordSalt);
        return { passwordHash, passwordSalt }
    }




    async register(req, resp, next) {
        const existingUser = await db.User.findOne({
            where: {
                [db.Op.or]: {
                    email: req.body.username,
                    phone: req.body.username.replace(/\s+/g, '')
                }
            }
        });
        if (existingUser != null) {
            resp.status(400).send({ error: 'already exists' });
            console.log('user already exists!!!');
            return;
        } else {
            console.log('no such user yet, continue registration');
        }

        const { passwordHash, passwordSalt } = this.createPasswordPair(req.body.password);
        const isUsernamePhone = /^[0-9\+\s]+$/gi.test(req.body.username);
        console.log('User is registering with phone number: ', isUsernamePhone);

        const user = await db.User.create({
            email: isUsernamePhone ? null : req.body.username,
            phone: isUsernamePhone ? req.body.username.replace(/\s+/g, '') : null,
            passwordHash,
            passwordSalt,
            valid: false,
            level: UserLevels.user
        });
        // TODO: add user email / phone validation
        async function generateCodeForPhone() {
            let res = "";
            let symb = "012346789";
            for (let i = 0; i <= 4; i++) {
                let item = symb[Math.floor(Math.random() * symb.length)]
                res += item
            }
            return res
        }
        async function generateCodeForEmail() {
            let res = "";
            let symb = "012346789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
            for (let i = 0; i <= 9; i++) {
                let item = symb[Math.floor(Math.random() * symb.length)]
                res += item
            }
            return res
        }
        const randomCodeEmail = await generateCodeForEmail();
        const randomCodePhone = await generateCodeForPhone();
        if (user.email != null) {
            const acc = await db.AccountValidation.create({
                user_id: user.id,
                code: randomCodeEmail,
                expireAt: moment().add(30, 'minutes').toDate()
            })
        } else {
            const acc2 = await db.AccountValidation.create({
                user_id: user.id,
                code: randomCodePhone,
                expireAt: moment().add(30, 'minutes').toDate()
            })
        }
        // Sgenerit' kod (new user.id) expire_at + 30 min)
        resp.send('ok');
    }

    async check(req, resp, next) {
        const user = await db.User.findByPk(req.params.id)
        const acc = await db.AccountValidation.findOne({
                where: {
                    user_id: user.id
                }
            })
            // check by phone                     check by email
        if (acc.code === req.body.code || acc.code === req.query.code) {
            const validate = await user.update({
                valid: true
            })
            const destroy = await acc.destroy()
        } else {
            console.log('hnik hnik');
        }
        resp.send('ok')
    }

    async destroy(req, resp, next) {
        const user = await db.User.findByPk(req.params.id);
        if (user == null) {
            console.log('no such user');

        }
        const del = await user.destroy();
        resp.send('deleted')
    }



    async setInterval() {
        setInterval(this.service.bind(this), 1000 * 90),
            setInterval(this.authStrategy.bind(this), 1000 * 60)

    }

    async service() {
        let allAcs = await db.AccountValidation.findAll({
            where: {
                expireAt: {
                    [db.Op.lt]: moment().toDate()
                }
            }
        })
        for (let acc of allAcs) {
            let destr = await db.User.destroy({
                where: {
                    id: acc.user_id
                }
            })
        }
    }

    async authStrategy() {
        let expTokens = await db.UserAuth.findAll({
            where: {
                expireAt: {
                    [db.Op.lt]: moment().toDate()
                }
            }
        })
        for (let token of expTokens) {
            console.log(token.user_id);
            let destr = await db.UserAuth.destroy({
                where: {
                    user_id: token.user_id
                }
            })
            let newTokensPair = await db.UserAuth.create({
                user_id: token.user_id,
                token: crypto.randomBytes(32).toString('hex'),
                refreshToken: crypto.randomBytes(32).toString('hex'),
                expireAt: moment().add(15, 'minutes').toDate()
            })
        }
    }


    async one(req, resp) {
        const dbuser = await this.model.findByPk(req.params.id, {
            attributes: {
                exclude: ['passwordHash', 'passwordSalt']
            }
        });
        resp.send(dbuser);
    }

    async add(req, resp) {
        const { passwordHash, passwordSalt } = this.createPasswordPair(req.body.password);
        const object = await db.User.create({
            ...req.body,
            passwordHash,
            passwordSalt
        });
        resp.sendStatus(200);
    }

    createRoutes(router) {
        router.post('/login', this.wrap(this.login));
        router.post('/register', this.wrap(this.register));
        // check by phone
        router.post('/check/:id', this.wrap(this.check));
        // check by email
        router.post('/check/:id', this.wrap(this.check)); // was get
        router.delete('/destroy/:id', this.wrap(this.destroy))
        this.router.get('/logout', this.ctx.authUser, this.wrap(this.logout));
        this.auth = this.ctx.authAdmin;
        super.createRoutes(router);
    }
}

module.exports = UserService;