import dotenv from 'dotenv';
dotenv.config();

const OPCION_DATOS =  'mongodb'

//console.log(process.env.MONGO_DB_URI)

export default {
    OPCION_DATOS,
    fileSystem: {
        path: './DB'
    },
    mongodb: {
        uri: process.env.MONGO_DB_URI ,
        nombreDb: process.env.NOMBRE_DB,
        options: {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true,
            serverSelectionTimeoutMS: 5000
        }
    }
}
