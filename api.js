/************************CONFIG****************************/
const express = require('express')
const app = express()

const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');

const cors = require('cors')
app.use(cors())

app.use(express.urlencoded({ extended: false }))
app.use(express.json())
var pg = require('pg')
var consString = process.env.DATABASE_URL;
var port = process.env.PORT;
const login = require('./Middleware/login')

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }})


/************************USUARIO**************************/

app.get('/', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        res.status(200).send('Conectado com sucesso!')
        client.release()
    })
})


app.post('/usuarios', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada')
        }
        client.query('select * from usuarios where email = $1', [req.body.email], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }

            if (result.rowCount > 0) {
                return res.status(200).send('Email já cadastrado')
            }
            bcrypt.hash(req.body.senha, 10, (error, hash) => {
                if (error) {
                    return res.status(500).send({
                        message: 'Erro de autenticação',
                        erro: error.message
                    })
                }
                var sql = 'insert into usuarios (nome, email, cpf, senha, perfil) values ($1, $2, $3, $4, $5)'
                client.query(sql, [req.body.nome, req.body.email, req.body.cpf, hash, req.body.perfil], (error, result) => {
                    if (error) {
                        return res.status(403).send('Operação não permitida')
                    }
                    res.status(201).send({
                        mensagem: 'criado com sucesso',
                        status: 201
                        
                    })
                    client.release()
                })
            })
        })
    })
})


app.get('/usuarios', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from usuarios', (error, result) => {
            if (error) {
                return res.status(401).send('Não foi possível realizar a consulta!')
            }
            res.status(200).send(result.rows)
            client.release()
        })
    })
})

app.get('/usuarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from usuarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send(result.rows[0])
            client.release()
        })
    })
})

app.delete('/usuarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('delete from usuarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send({
                mensagem: 'Usuário deletado com sucesso!',
                status: 201
            })
            client.release()
        })
    })
})

app.put('/usuarios/:id', (req, res) => {
    //res.status(200).send('Rota update criada')
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from usuarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            // update usuarios set senha = $1, perfil = $2 where email=$3
            if (result.rowCount > 0) {
                var sql = 'update usuarios set nome = $1, email = $2, cpf = $3, senha = $4, perfil = $5     where id = $6'
                let valores = [req.body.nome, req.body.email, req.body.cpf, req.body.senha, req.body.perfil, req.body.id]
                client.query(sql, valores, (error2, result2) => {
                    if (error2) {
                        return res.status(401).send('Operação não permitida!')
                    }
                    if (result2.rowCount > 0) {
                        return res.status(200).send('Usuário alterado com sucesso!')
                    }
                })
            } else
                res.status(200).send('Usuário não encontrado na base de dados!')
                client.release()

        })
    })
})

app.post('/usuarios/login', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send("Conexão não autorizada")
        }
        client.query('select * from usuarios where email = $1', [req.body.email], (error, result) => {
            if (error) {
                return res.status(401).send('operação não permitida')
            }
            if (result.rowCount > 0) {
                //cripotgrafar a senha enviada e comparar com a recuperada do banco
                bcrypt.compare(req.body.senha, result.rows[0].senha, (error, results) => {
                    if (error) {
                        return res.status(401).send({
                            message: "Falha na autenticação"
                        })
                    }
                    if (results) { //geração do token
                        let token = jwt.sign({
                            email: result.rows[0].email,
                            perfil: result.rows[0].perfil
                        },
                            process.env.JWTKEY, { expiresIn: '2h' })
                        return res.status(200).send({
                            message: 'Conectado com sucesso',
                            token: token
                        })
                    }
                })
            } else {
                return res.status(200).send({
                    message: 'usuário não encontrado'
                })
            }
        })
    })
})

/************************SERVICOS***************************/

app.get('/', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        res.status(200).send('Conectado com sucesso!')
        client.release()
    })
})

app.post('/servicos', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from servicos where nome = $1', [req.body.nome], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }

            if (result.rowCount > 0) {
                return res.status(200).send('Serviço já cadastrado!')
            }

            var sql = 'insert into servicos (nome, descricao, preco, duracao, status) values ($1, $2, $3, $4, $5)'
            client.query(sql, [req.body.nome, req.body.descricao, req.body.preco, req.body.duracao, req.body.status], (error, result) => {
                if (error) {
                    return res.status(403).send('Operação não permitida!')
                }
                res.status(201).send({
                    mensagem: 'Serviço criado com sucesso!',
                    status: 201
                })
            })

        })
    })
})


app.get('/servicos', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from servicos', (error, result) => {
            if (error) {
                return res.status(401).send('Não foi possível realizar a consulta!')
            }
            res.status(200).send(result.rows)
            client.release()
        })
    })
})

app.get('/servicos/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from servicos where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send(result.rows[0])
            client.release()
        })
    })
})

app.delete('/servicos/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('delete from servicos where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send({
                mensagem: 'Serviço deletado com sucesso!',
                status: 201
            })
            client.release()
        })
    })
})

app.put('/servicos/:id', (req, res) => {
    //res.status(200).send('Rota update criada')
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from servicos where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            // update usuarios set senha = $1, perfil = $2 where email=$3
            if (result.rowCount > 0) {
                var sql = 'update servicos set nome = $1, descricao = $2, preco = $3, duracao = $4, status = $5     where id = $6'
                let valores = [req.body.nome, req.body.descricao, req.body.preco, req.body.duracao, req.body.status, req.body.id]
                client.query(sql, valores, (error2, result2) => {
                    if (error2) {
                        return res.status(401).send('Operação não permitida!')
                    }
                    if (result2.rowCount > 0) {
                        return res.status(200).send('Servico alterado com sucesso!')
                    }
                })
            } else
                res.status(200).send('Serviço não encontrado na base de dados!')
                client.release()

        })
    })
})

/************************AGENDAMENTO***************************/

app.get('/', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        res.status(200).send('Conectado com sucesso!')
        client.release()
    })
})



app.post('/horarios', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from horarios where email = $1', [req.body.email], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }

            if (result.rowCount > 0) {
                return res.status(200).send('Você já realizou agendamento!')
            }

            var sql = 'insert into horarios (nome, telefone, email, dia, horario, procedimento, observacao) values ($1, $2, $3, $4, $5, $6, $7)'
            client.query(sql, [req.body.nome, req.body.telefone, req.body.email, req.body.dia, req.body.horario, req.body.procedimento, req.body.observacao], (error, result) => {
                if (error) {
                    return res.status(403).send('Operação não permitida!')
                }
                res.status(201).send({
                    mensagem: 'Agendamento criado com sucesso!',
                    status: 201
                })
                client.release()
            })

        })
    })
})


app.get('/horarios', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from horarios', (error, result) => {
            if (error) {
                return res.status(401).send('Não foi possível realizar a consulta!')
            }
            res.status(200).send(result.rows)
            client.release()
        })
    })
})

app.get('/horarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from horarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send(result.rows[0])
            client.release()
        })
    })
})

app.delete('/horarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('delete from horarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send({
                mensagem: 'Agendamento deletado com sucesso!',
                status: 201
            })
            client.release()
        })
    })
})

app.put('/horarios/:id', (req, res) => {
    //res.status(200).send('Rota update criada')
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from horarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            // update usuarios set senha = $1, perfil = $2 where email=$3
            if (result.rowCount > 0) {
                var sql = 'update horarios set nome = $1, telefone = $2, email = $3, dia = $4, horario = $5, procedimento = $6, observacao = $7 where id = $8'
                let valores = [req.body.nome, req.body.telefone, req.body.email, req.body.dia, req.body.horario, req.body.procedimento, req.body.observacao, req.body.id]
                client.query(sql, valores, (error2, result2) => {
                    if (error2) {
                        return res.status(401).send('Operação não permitida!')
                    }
                    if (result2.rowCount > 0) {
                        return res.status(200).send('Agendamento alterado com sucesso!')
                    }
                })
            } else
                res.status(200).send('Agendamento não encontrado na base de dados!')
                client.release()

        })
    })
})

/************************FUNCIONARIO***************************/

app.get('/', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        res.status(200).send('Conectado com sucesso!')
        client.release()
    })
})

app.post('/funcionarios', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from funcionarios where cpf = $1', [req.body.cpf], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }

            if (result.rowCount > 0) {
                return res.status(200).send('Funcionário já cadastrado!')
            }

            var sql = 'insert into funcionarios (nome, telefone, cpf, servico, descricao) values ($1, $2, $3, $4, $5)'
            client.query(sql, [req.body.nome, req.body.telefone, req.body.cpf, req.body.servico, req.body.descricao], (error, result) => {
                if (error) {
                    return res.status(403).send('Operação não permitida!')
                }
                res.status(201).send({
                    mensagem: 'Funcionário criado com sucesso!',
                    status: 201
                })
                client.release()
            })

        })
    })
})


app.get('/funcionarios', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from funcionarios', (error, result) => {
            if (error) {
                return res.status(401).send('Não foi possível realizar a consulta!')
            }
            res.status(200).send(result.rows)
            client.release()
        })
    })
})

app.get('/funcionarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from funcionarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send(result.rows[0])
            client.release()
        })
    })
})

app.delete('/funcionarios/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('delete from funcionarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send({
                mensagem: 'Funcionário deletado com sucesso!',
                status: 201
            })
            client.release()
        })
    })
})

app.put('/funcionarios/:id', (req, res) => {
    //res.status(200).send('Rota update criada')
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from funcionarios where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            // update usuarios set senha = $1, perfil = $2 where email=$3
            if (result.rowCount > 0) {
                var sql = 'update funcionarios set nome = $1, telefone = $2, cpf = $3,  servico= $4, descricao = $5     where id = $6'
                let valores = [req.body.nome, req.body.telefone, req.body.cpf, req.body.servico, req.body.descricao, req.body.id]
                client.query(sql, valores, (error2, result2) => {
                    if (error2) {
                        return res.status(401).send('Operação não permitida!')
                    }
                    if (result2.rowCount > 0) {
                        return res.status(200).send('Funcionário alterado com sucesso!')
                    }
                })
            } else
                res.status(200).send('Funcionário não encontrado na base de dados!')
                client.release()

        })
    })
})


/************************CLIENTES***************************/

app.get('/', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        res.status(200).send('Conectado com sucesso!')
        client.release()
    })
})

app.post('/clientes', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from clientes where cpf = $1', [req.body.cpf], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada')
            }

            if (result.rowCount > 0) {
                return res.status(200).send('Cliente já cadastrado!')
            }

            var sql = 'insert into clientes (nome, cpf, cidade, cep, estado, endereco, email, id_usuario) values ($1, $2, $3, $4, $5, $6, $7, $8)'
            client.query(sql, [req.body.nome, req.body.cpf, req.body.cidade, req.body.cep, req.body.estado, req.body.endereco, req.body.email, req.body.id_usuario], (error, result) => {
                if (error) {
                    return res.status(403).send('Operação não permitida!')
                }
                res.status(201).send({
                    mensagem: 'Cliente criado com sucesso!',
                    status: 201
                })
                client.release()
            })

        })
    })
})


app.get('/clientes', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from clientes', (error, result) => {
            if (error) {
                return res.status(401).send('Não foi possível realizar a consulta!')
            }
            res.status(200).send(result.rows)
            client.release()
        })
    })
})

app.get('/clientes/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('select * from clientes where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send(result.rows[0])
            client.release()
        })
    })
})

app.delete('/clientes/:id', (req, res) => {
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }
        client.query('delete from clientes where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            res.status(201).send({
                mensagem: 'cliente deletado com sucesso!',
                status: 201
            })
            client.release()
        })
    })
})

app.put('/clientes/:id', (req, res) => {
    //res.status(200).send('Rota update criada')
    pool.connect((err, client) => {
        if (err) {
            return res.status(401).send('Conexão não autorizada!')
        }

        client.query('select * from clientes where id = $1', [req.params.id], (error, result) => {
            if (error) {
                return res.status(401).send('Operação não autorizada!')
            }
            // update usuarios set senha = $1, perfil = $2 where email=$3
            if (result.rowCount > 0) {
                var sql = 'update clientes set nome = $1, cpf = $2, cidade = $3,  cep= $4, estado = $5, endereco = $6, email = $7, id_usuario = $8 where id = $9'
                let valores = [req.body.nome, req.body.cpf, req.body.cidade, req.body.cep, req.body.estado, req.body.endereco, req.body.email, req.body.id_usuario, req.body.id]
                client.query(sql, valores, (error2, result2) => {
                    if (error2) {
                        return res.status(401).send('Operação não permitida!')
                    }
                    if (result2.rowCount > 0) {
                        return res.status(200).send('Cliente alterado com sucesso!')
                    }
                })
            } else
                res.status(200).send('Cliente não encontrado na base de dados!')
                client.release()

        })
    })
})


app.listen(process.env.PORT || 8081, () => console.log('Servidor funcionando'))
