import { Router } from 'express';
import faker from 'faker'
import logger from '../src/logger.js'

faker.locale = 'es'

const routerProductos = new Router();

let id = 1
function getNextId() {
    return id++
}

function crearCombinacionAleatoria(id) {
    return {
        id,
        nombre: faker.commerce.product(),
        price: faker.commerce.price(),
        image: `${faker.image.imageUrl()}?random=${Math.round(Math.random() * 1000)}`// faker.image.imageUrl()
    }
}

const productosFake= async(req,res) => {
    const resultado=[]
    for (let i = 0; i < 5; i++) {
        resultado.push(crearCombinacionAleatoria(getNextId()))
    }
    logger.info(`Informacion mostrada con exito: /productos-test`);
    return res.json(resultado)
}

routerProductos.get('/productos-test', productosFake);

export {routerProductos}