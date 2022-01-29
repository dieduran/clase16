import log4js from "log4js";

log4js.configure({
  appenders: {
    consola: { type: "console" },
    archivoWarnings: { type: "file", filename: "warn.log" },
    archivoErrores: { type: "file", filename: "error.log" },
    loggerConsola: {
      type: "logLevelFilter",
      appender: "consola",
      level: "info",
    },
    loggerArchivoWarnings: {
      type: "logLevelFilter",
      appender: "archivoWarnings",
      level: "warn",
    },
    loggerArchivoErrores: {
      type: "logLevelFilter",
      appender: "archivoErrrores",
      level: "error",
    },
  },
  categories: {
    default: {
      appenders: [
        "loggerConsola",
        "loggerArchivoWarnings",
        "loggerArchivoErrores",
      ],
      level: "all",
    },
  },
});

const logger = log4js.getLogger();

export default logger;
