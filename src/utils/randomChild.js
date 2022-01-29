const minimoRandom=1
const maximoRandom=1000
const cantidadDefault= 100000000

const numerosRandom  = (cant) => {
    if (cant==0 || Number.isNaN(cant)||Number.isNaN(parseInt(cant))) {
        console.log('aplicamos cantidadDefault')
        cant=cantidadDefault //sin valor
    }
    let resultado = {};
    for (let i = 0; i < cant; i++) {
        let numeroAleatorio = Math.floor((Math.random() * (maximoRandom)) + minimoRandom);
        if (resultado[numeroAleatorio]) {
            resultado[numeroAleatorio] += 1;
        } else {
            resultado[numeroAleatorio] = 1;
        }
    }
    return resultado;
};

process.on('message', msg => {
    console.log(`mensaje del padre: ${msg}`)
    const resultado = numerosRandom(msg);
    //process.send(JSON.stringify(resultado))
    process.send(resultado)
    process.exit()
})

process.send('listo')
