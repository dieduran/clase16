
import { Router } from "express";
import compression from "compression";
import logger from "../src/logger.js";

const routerInfo = new Router();

import os  from 'os'

const objetoDatos={
            Arg: process.argv.slice(2), 
            SO: process.platform,
            Node: process.version,       
            Memoria: process.memoryUsage().rss,
            execPath: process.execPath,
            PID: process.pid, 
            ProjectFolder: process.cwd(),
            NroProcesadores: os.cpus().length
        }

        
routerInfo.get('/', async(req,res) => {
    res.json(objetoDatos)
    logger.info(`Informacion mostrada con exito`);
    }
);

routerInfo.get('/comprimida', compression(), (req, res) => {
    res.json(objetoDatos)
    logger.info(`Informacion comprimida mostrada con exito`);
    }
);

routerInfo.get("/consolelog", (req, res) => {
    console.log(objetoDatos)
    res.json(objetoDatos)
    logger.info(`Informacion mostrada con exito y tambien en el Console Log`);
  });
  


export {routerInfo}
