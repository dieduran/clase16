import dotenv from 'dotenv';
dotenv.config();

import express from  'express'
import handlebars from 'express-handlebars'
import path from 'path'
import fetch from 'node-fetch'
import Yargs from 'yargs'
import cluster from 'cluster'
import os from 'os'
import logger from "../src/logger.js";

const parametros = Yargs(process.argv.slice(2))
                      .alias({
                        p: 'puerto',
                        m: 'modo'
                      })
                      .default({
                        puerto: '8080',
                        modo: 'FORK'
                      })
                      .argv

const PORT=parametros.puerto  //ahora por parametro de linea de comando
const MODO=parametros.modo    //parametro de linea de comando
//console.log(parametros)

import { normalize, schema } from "normalizr";
/** para manejo de sesion */
import session from 'express-session'
import config from  '../src/options/config.js'
/** passport  */
import passport  from 'passport'
import bcrypt from 'bcrypt'
import {Strategy as LocalStrategy} from 'passport-local';

import { Server as HttpServer } from  'http'
import { Server as Socket } from 'socket.io'

import {conectarDB} from './options/conexionBD.js'
import {User} from '../models/modelUser.js'
import ContenedorMongoD from '../contenedores/ContenedorMongoDb.js'
import {routerProductos} from '../routes/routerProducto.js'
import {routerInfo} from '../routes/routerInfo.js'
import {routerRandom} from '../routes/routerRandom.js'
import {getRegistro, getLoginError, getRegistroError, errorRuteo } from '../controllers/login.js'

const app = express()
const httpServer = new HttpServer(app)
const io = new Socket(httpServer)

const productos= new ContenedorMongoD('productosEje11')
const mensajes= new ContenedorMongoD('mensajesEje11')

let usuario;

/*-----------------------------------------*/
const advancedOptions = { useNewUrlParser: true, useUnifiedTopology: true }
 
passport.use('signup', new LocalStrategy({
    passReqToCallback: true
    },
    (req, username, password, done) => {
      User.findOne({ 'username': username }, function (err, user) {
    
        if (err) {
          //console.log('Error in SignUp: ' + err);
          logger.error("Error in SignUp: " + err);
          return done(err);
        }
    
        if (user) {
          logger.info('User already exists');
          //console.log('User already exists');
          return done(null, false)
        }
        const newUser = {
          username: username,
          password: createHash(password),
          email: req.body.email,
          firstName: req.body.firstName,
          lastName: req.body.lastName,
        }
        User.create(newUser, (err, userWithId) => {
            if (err) {
              console.log('Error in Saving user: ' + err);
              return done(err);
            }
            //console.log('User Registration succesful');
            logger.info('User Registration succesful');
            return done(null, userWithId);
          });
        });
  })
)

  passport.use('login', new LocalStrategy(
    (username, password, done) => {
      User.findOne({ username }, (err, user) => {
        if (err)
          return done(err);
        if (!user) {
          logger.info('User Not Found with username ' + username);
          return done(null, false);
        }
        if (!isValidPassword(user, password)) {
          logger.info('Invalid Password');
          return done(null, false);
        }
        return done(null, user);
      });
    })
);

function isValidPassword(user, password) {
    return bcrypt.compareSync(password, user.password);
}
     
function createHash(password) {
  return bcrypt.hashSync( password, bcrypt.genSaltSync(10), null);
}

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, done);
});
   
app.use(
    session({
      secret: "coderhouse",
      cookie: {
        httpOnly: false,
        secure: false,
        maxAge: 60*10*1000,
      },
      rolling: true,
      resave: true,
      saveUninitialized: false,
  })
);

/*-----------------------------------------*/
const cargarProductoRandom = async() =>{
  let rdo
  await fetch(`http://localhost:${PORT}/api/productos-test`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' }
  }).then(res => res.json())
    .then(json => rdo=json);   
    return rdo
}

const getAllNormalizados= async()=>{//    getAll(): Object[] - Devuelve un array con los objetos presentes en el archivo.
  try{
      const originalData= await mensajes.getAll();
      let auxData= new Object({id: 'mensajes', mensajes: originalData})
      const tamanioAntes = JSON.stringify(originalData).length

      const authorSchema = new schema.Entity('author',{idAttribute:"id"});
      const messageSchema = new schema.Entity('mensaje',{
          author: authorSchema})
      const allMessageSchema= new schema.Entity('mensajes',{
          mensajes:[ messageSchema]});
      const normalizedData = normalize(auxData,allMessageSchema);
      
      const tamanioDespues= JSON.stringify(normalizedData).length
      const dataIntegrada= new Object({antes: tamanioAntes, despues: tamanioDespues, mensajesNormalizado: normalizedData })
      //return normalizedData
      return dataIntegrada
  }catch(error){
      //const contenido = []
      const dataIntegrada= new Object({antes: 0 , despues: 0, mensajesNormalizado: [] })
      return dataIntegrada // JSON.parse(contenido)
  }
}


//--------------------------------------------
// configuro el socket
io.on('connection', async socket => {
  //console.log('Nuevo cliente conectado!');
  logger.info('Nuevo cliente conectado!');

  // carga inicial de producto
  socket.emit('productos',await productos.getAll())

  // carga inicial de productosRandom
  socket.emit('productosRandom',await cargarProductoRandom())
  
  // actualizacion de producto
  socket.on('updateProducto', async producto => {
      await productos.save(producto)
      io.sockets.emit('productos', await productos.getAll());
  })

  // carga inicial de mensajes
  socket.emit('mensajes', await getAllNormalizados())//  await mensajes.getAll())

  socket.emit('cargarDatosSesion',await cargarDatosSesion())

  // actualizacion de mensajes
  socket.on('updateMensaje', async mensaje => {
      await mensajes.save(mensaje)
      io.sockets.emit('mensajes', await getAllNormalizados())// await mensajes.getAll())
  })
});


//**  Manejador de plantillas */
app.engine('hbs', handlebars({
  extname: 'hbs',
  defaultLayout: 'default',
  layoutDir: "/views/layouts",
}))

app.set('view engine', 'hbs');
//app.set('views', "./views");
app.set('views', path.join(process.cwd(), 'public/views'));

//--------------------------------------------
// agrego middlewares
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static('public'))

app.use(passport.initialize());
app.use(passport.session());
    
function checkAuthentication(req, res, next) {
  if (req.isAuthenticated()) {
    next();
  } else {
    res.redirect("/login");
  }
}

app.use('/api',routerProductos)
app.use('/info', routerInfo)
app.use('/api/randoms', routerRandom)

//Routers
app.get('/',checkAuthentication, (req, res) => {
      usuario =req.user.username
      res.redirect('principal.html')
  })

app.get('/login', (req, res) => {
  if (req.isAuthenticated()) { 
    res.redirect("/");
  } else {
    res.sendFile("formLogin.html", { root: "./public" });
  }
});

app.post('/login', 
  passport.authenticate("login", {
    failureRedirect: "/faillogin",
    successRedirect: "/",
  })
);

app.get("/signup", getRegistro);

app.post("/signup",
  passport.authenticate("signup", {
    failureRedirect: "/failsignup",
    successRedirect: "/login",
  })
);

app.get("/failsignup", getRegistroError);

app.post("/login",        
  passport.authenticate("login", {
    failureRedirect: "/faillogin",
    successRedirect: "/",
  })
);

app.get("/faillogin", getLoginError);

app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (!err) {
            usuario= "";
            res.sendFile('formLogout.html',{ root: './public' })
        } else {
            //console.log('logout error')
            logger.error('Logout ERROR ', err)
            res.send({ status: 'Logout ERROR', body: err })
        }
    })
})

// app.get("/logout", (req, res) => {
//   req.logout();
//   res.redirect("/");
// });

app.get("*", errorRuteo);

conectarDB(
  //"//cadena de conexion a mongoAtlas",
  process.env.MONGO_DB_URI,
  (err) => {
    if (err) {
      logger.error("error en conexión de base de datos", err);
      return 
    }
    logger.info("Base de datos conectada...");
  }
);

const cargarDatosSesion =async()=> {
    return {usuario}
}

//--------------------------------------------
// inicio el servidor

/** FORMA ANTERIOR */
//--------------------------------------------
// const server = httpServer.listen(PORT, () => {
//     console.log(`Conectado al puerto ${PORT}`)
// })
// server.on('error', (error) => {
//     console.log('Ocurrio un  error...')
//     console.log(error)
// })

/** FORMA NUEVA */
//--------------------------------------------
// Cargo el server
if(MODO=='CLUSTER' && cluster.isMaster) {
  const numCPUs = os.cpus().length
  
  logger.info(`Número de procesadores: ${numCPUs}`)
  logger.info(`PID MASTER ${process.pid}`)

  for(let i=0; i<numCPUs; i++) {
      cluster.fork()
  }

  cluster.on('exit', worker => {
      //console.log('Worker', worker.process.pid, 'died', new Date().toLocaleString())
      logger.info('Worker', worker.process.pid, 'died', new Date().toLocaleString())
      cluster.fork()
  })
}else{
  const server = httpServer.listen(PORT, () => {
    logger.info(`Servidor HTTP escuchando en el puerto ${server.address().port} - PID WORKER ${process.pid}`)
    })
    server.on("error", error => logger.error(`Error en servidor ${error}`))
}
/** */
