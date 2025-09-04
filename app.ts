/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import winston from 'winston';

const logger = winston.createLogger({
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'security.log' })
  ]
});

async function app () {
  const { default: validateDependencies } = await import('./lib/startup/validateDependenciesBasic');
  await validateDependencies();

  const server = await import('./server');
  await server.start();

  // Log application start
  logger.info('Application started');
}

app()
  .catch(err => {
    logger.error(`Application failed to start: ${err}`);
    throw err;
  });
