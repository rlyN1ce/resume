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
        setInterval(this.service.bind(this), 1000 * 60),
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
        let allExp = await db.PasswordRecoveryRequests.findAll({
            where:{
                expireAt:{
                    [db.Op.lt]:moment().toDate()
                }
            }
        })
        // let destrExp = await allExp.destroy()
        for (let exp of allExp){
            let destrExp = await db.PasswordRecoveryRequests.destroy({
                where:{
                    id:exp.user_id
                }
            })
        }
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

    async updateUser(req, resp) {
        const user = await db.User.findOne({
            where: {
                id: req.params.id
            }
        })
            const update = await user.update({
                    email: req.body.email,
                    phone: req.body.phone,
            })        
        resp.send({
            email:req.body.email
        })
    }





// generate newCode , create prr, email
// check pgmodeler
async generateNewCode(req,resp){
    let user = await db.User.findOne({
        where:{
            id:req.params.id
        },
        
    })
    console.log(user.id);
    async function generateCodeForEmail() {
        let res = "";
        let symb = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
        for (let i = 0; i <= 9; i++) {
            let item = symb[Math.floor(Math.random() * symb.length)]
            res += item
        }
        return res
    }
    const newCode= await generateCodeForEmail();
    console.log(newCode);
    // console.log(user.Auths.token);
        // if (user.Auths.token === req.query.token){
            let myCode = await db.PasswordRecoveryRequests.create({            
                user_id:user.id,
                token: newCode,
                expireAt:moment().add(10,'minutes').toDate()            
        })     
        
    
    resp.sendStatus(200, 'OK')
}




    async PasswordRecoveryRequests(req,resp) {
        let user = await db.User.findOne({
                where: {
                    id: req.params.id
                },
                include: [
                    { model: db.UserAuth, as: 'Auths' },
                    { model: db.PasswordRecoveryRequests, as: 'PRR' }
                ]
            })
            console.log(user.PRR);

        for (let prr of user.PRR) {
            if (prr.token === req.body.token || prr.token === req.query.token) {
                let destrPrr = await prr.destroy();
                for (let auth of user.Auths) {
                    let destrAuth = await auth.destroy();
                }               
            }
        }
        let newPair = await db.UserAuth.create({
            user_id: user.id,
            token: crypto.randomBytes(32).toString('hex'),
            refreshToken: crypto.randomBytes(32).toString('hex'),
            expireAt: moment().add(10, 'minutes').toDate()
        })
        resp.send({
            user_id: user.id,
            token: newPair.token,
            refreshToken: newPair.refreshToken
        })
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

        router.put('/update/:id', this.wrap(this.updateUser))

        router.post('/resetpassword/:id',this.wrap(this.generateNewCode))

        router.post('/newpassword/:id', this.wrap(this.PasswordRecoveryRequests))

        router.delete('/destroy/:id', this.wrap(this.destroy))
        this.router.get('/logout', this.ctx.authUser, this.wrap(this.logout));
        this.auth = this.ctx.authAdmin;
        super.createRoutes(router);
    }
}