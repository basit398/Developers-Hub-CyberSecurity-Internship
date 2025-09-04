import helmet from 'helmet'
import express from 'express'
import compression from 'compression'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import bodyParser from 'body-parser'
import config from 'config'
import errorhandler from 'errorhandler'

const app = express()

// ✅ Helmet FIRST
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for Juice Shop
  crossOriginEmbedderPolicy: false,
  frameguard: { action: 'SAMEORIGIN' },
  referrerPolicy: { policy: 'no-referrer' },
  dnsPrefetchControl: { allow: false }
}))

app.disable('x-powered-by')

// ✅ Other Middlewares
app.use(compression())
app.use(cors())
app.use(cookieParser())
app.use(bodyParser.json({ limit: '2mb' }))
app.use(bodyParser.urlencoded({ extended: true, limit: '2mb' }))

if (process.env.NODE_ENV === 'development') {
  app.use(errorhandler())
}

const port = config.get<number>('server.port') || 3000

export async function start () {
  return app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`)
  })
}

export default app
