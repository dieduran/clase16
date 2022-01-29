import { Router } from "express";
import { fork } from 'child_process'
import path from 'path'
const routerRandom = new Router();

const funcionRandom= async(req,res) => {
    const {cant= 0} =req.query

    const fileName= path.join(process.cwd(), '/src/utils/randomChild.js')
    const forked = fork(fileName)

    forked.on('message', msg => {
        if (msg == 'listo') {
            forked.send(cant)
        } else {
            //console.log(`Mensaje del hijo: ${msg}`)
            //devolvemos respuesta del hijo
            res.json(msg)
        }
    })
}

routerRandom.get('/', funcionRandom);

export {routerRandom}