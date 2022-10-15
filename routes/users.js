const express = require('express');
const User = require('../models/User.js');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

//Register
router.post('/register', (req, res) => {

    User.findOne({ email: req.body.email }).then(data => {
        if (data) res.json({ message: 'Email is already being used' })
        else {
            const user = new User({
                firstName: req.body.firstName,
                lastName: req.body.lastName,
                username: req.body.username,
                email: req.body.email,
                phone: req.body.phone,
                password: req.body.password,
                address: req.body.address
            });

            bcrypt.genSalt(10, (err, salt) => {
                if (err) res.json(err);
                bcrypt.hash(user.password, salt, (err, hash) => {
                    if (err) res.json(err);
                    user.password = hash;
                    user.save()
                        .then(data => {
                            user.password = undefined;
                            const token = jwt.sign(user.toJSON(), process.env.SECRET, {
                                expiresIn: 7200 // 2h
                            });
                            res.json({
                                success: true,
                                token: 'JWT ' + token
                            })
                        })
                        .catch(err => {
                            res.json(err);
                        });
                })
            })
        }
    })


})



router.post('/verifieremail', (req, res) => {
    User.findOne({ email: req.body.email }).then(data => {
        if (data != null) {
            res.json(true)
        } else {
            res.json(false)
        }
    })
})

router.post('/verifierlogin', (req, res) => {
    User.findOne({ login: req.body.login }).then(data => {
        if (data != null) {
            res.json(true)
        } else {
            res.json(false)
        }
    })
})



router.post('/authenticate', (req, res, next) => {
    const login = req.body.login;
    const password = req.body.password;
    User.findOne({ login: login }, (err, user) => {
        if (!user) {
            return res.json({ success: false, error: "Utilisateur non trouvé" });

        }
        User.comparePassword(password, user.password, (err, isMatch) => {
            if (err) res.json(err);
            if (isMatch) {
                user.password = undefined;
                const token = jwt.sign(user.toJSON(), process.env.SECRET, {
                    expiresIn: 7200 // 2h
                });


                // **************************************** LOCAL STORAGE **********************************
                res.json({
                    success: true,
                    token: 'JWT ' + token
                })
                //********************************************************
            } else {
                return res.json({ success: false, error: 'Mot de passe incorrect !' });
            }
        })
    })
});

router.post('/savePassword', (req, res) => {
    let reqBody = req.body;
    bcrypt.genSalt(10, (err, salt) => {
        if (err) res.json(err);
        bcrypt.hash(reqBody.password, salt, (err, hash) => {
            if (err) res.json(err);
            reqBody.password = hash;

            User.findOne({ login: reqBody.login }, (err, user) => {
                if (!user) {
                    return res.json({ success: false, error: "Utilisateur non trouvé" });
                }
                user.screenPassword = reqBody.password;
                user.save().then(data => {
                    return res.json({ success: true, error: "Mot de passe enregistré" });
                })
            })
        })
    })


})

router.post('/checkPassword', (req, res, next) => {
    const login = req.body.login;
    const password = req.body.password;
    User.findOne({ login: login }, (err, user) => {
        if (!user) {
            return res.json({ success: false, error: "Utilisateur non trouvé" });
        }
        User.comparePassword(password, user.screenPassword, (err, isMatch) => {
            if (err) res.json(err);
            console.log(isMatch)

            if (isMatch) {
                // **************************************** LOCAL STORAGE **********************************
                res.json({
                    success: true,
                    message: "Mot de passe correct"
                })
                //********************************************************
            } else {
                return res.json({ success: false, error: 'Mot de passe incorrect !' });
            }
        })
    })
});

router.post('/checkPasswordAvailability', (req, res, next) => {
    const login = req.body.login;

    User.findOne({ login: login }, (err, user) => {
        if (!user) {
            return res.json({ success: false, error: "Utilisateur non trouvé" });
        }
        if (user.screenPassword == "" || user.screenPassword == null || user.screenPassword == undefined) {
            return res.json({ success: false, error: "Pas de mot de passe ajouté" });
        } else {
            return res.json({ success: true, error: "Mot de passe est disponible" });
        }
    })
});

router.get('/profile', passport.authenticate('jwt', { session: false }), (req, res, next) => {
    res.json({ user: req.user })
});


router.get('/', async (req, res) => {
    try {
        const users = await User.find();
        res.json({ status: 200, message: "Liste des clients", result: users });
    } catch (err) {
        res.json({ message: err });
    }
});

router.get('/:id', (req, res) => {
    User.findById(req.params.id, (err, user) => {
        user.password = "";
        res.json(user);
    });
});



router.put('/:id', (req, res) => {
    User.findById(req.params.id, (err, user) => {

        user.lastName = req.body.lastName;
        user.firstName = req.body.firstName;
        user.address = req.body.address;
        user.phone = req.body.phone;
        user.login = req.body.login;
        user.email = req.body.email;
        user.password = req.body.password ? req.body.password : user.password;

        user.save().then(data => {
            res.json({ message: "Updated successfully!", status: 200 })
        }).catch(err => {
            res.json({ message: err });
        })
    });
});

router.put('/mdp/:id', (req, res) => {
    User.findById(req.params.id, (err, user) => {
        User.comparePassword(req.body.ancienneMdp, user.password, (err, isMatch) => {
            if (err) res.json(err);
            if (isMatch) {

                user.password = req.body.nouvelleMdp;
                bcrypt.genSalt(10, (err, salt) => {
                    if (err) res.json(err);
                    bcrypt.hash(user.password, salt, (err, hash) => {
                        if (err) res.json(err);
                        user.password = hash;
                        user.save().then(data => {
                            res.json({ message: "Mot de passe modifié !" })
                        }).catch(err => {
                            res.json({ message: err });
                        })
                        res.json({
                        })
                    })
                })


            } else {
                return res.json({ success: false, msg: 'mot de passe!' });
            }
        })


    });
});


router.delete('/:id', (req, res) => {
    User.findByIdAndRemove(req.params.id)
        .then(data => {
            res.json({ message: "user deleted" });
        })
        .catch(err => {
            res.json({ message: "error" });
        });
});

module.exports = router;