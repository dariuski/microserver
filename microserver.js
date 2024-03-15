/**
 * MicroServer v1.9.2
 * @copyright Darius Kisonas 2022
 * @license MIT
 */

import http from 'http'
import https from 'https'
import net from 'net'
import tls from 'tls'
import querystring from 'querystring'
import stream from 'stream'
import fs from 'fs'
import path from 'path'
import crypto from 'crypto'
import { EventEmitter } from 'events'

function NOOP () { }
class Warning extends Error {
  constructor (text) {
    super(text)
    this.name = 'Warning'
  }
}

export class ServerRequest extends http.IncomingMessage {
  /** @param {Object} body */
  /** @param {MicroServer} server */

  updateUrl () {
    const parsedUrl = new URL(this.url, 'body:/'), pathname = parsedUrl.pathname
    this.pathname = pathname
    this.path = pathname.slice(pathname.lastIndexOf('/'))
    this.baseUrl = pathname.slice(0, pathname.length - this.path.length)
    this.get = {}
    parsedUrl.searchParams.forEach((v, k) => this.get[k] = v)
  }
  
  get body () {
    if (!this._body) {
      if (this.method === 'GET')
        this._body = {}
      else {
        const contentType = this.headers['content-type'] || '',
          charset = contentType.match(/charset=(\S+)/)
        let body = Buffer.concat(this.rawBody).toString(charset ? charset[1] : 'utf8')
        if (body.startsWith('{') || body.startsWith('[')) {
          try {
            body = JSON.parse(body)
          } catch {
            throw new Error('Invalid request format')
          }
        } else if (contentType.startsWith('application/x-www-form-urlencoded')) {
          body = querystring.parse(body)
        } else {
          body = {}
        }
        this._body = body
      }
    }
    return this._body
  }

  get post () {
    return this.body
  }

  files () {
    this.resume()
    this.removeHeader('Connection')
    if (this._files.resolve !== NOOP)
      throw new Error('Invalid request files usage')
    return new Promise((resolve, reject) => {
      this._files.resolve = err => {
        this._files.done = true
        this._files.resolve = NOOP
        if (err) reject(err)
        else resolve(this._files.list)
      }
      if (this._files.done)
        this._files.resolve()
    })
  }

  bodyChunkInit(res, next) {
    const contentType = (this.headers['content-type'] || '').split(';')
    if (contentType.includes('multipart/form-data')) {
      this.pause()
      res.setHeader('Connection', 'close')
      this._body = {}
      this._files = {
        list: [],
        uploadDir: path.resolve(this.server.config.uploadDir || 'upload'),
        resolve: NOOP
      }
      if (!contentType.find(l => {
        const p = l.indexOf('boundary=')
        if (p >= 0) {
          this._files.boundary = '\r\n--' + l.slice(p + 9).trim()
          return true
        }
      }))
        return res.error(400)
      next()
      this.once('error', () => this._files.resolve(new Error('Request error')))
        .on('data', chunk => this.bodyChunkDecode(chunk))
        .once('end', () => this._files.resolve(new Error('Request error')))

      res.on('finish', () => req.removeTempFiles())
      res.on('error', () => req.removeTempFiles())
    } else {
      this.once('error', err => console.error(err))
        .on('data', chunk => {
          this.rawBodySize += chunk.length
          if (this.bodySize >= this.server.config.maxBodySize) {
            this.pause()
            res.setHeader('Connection', 'close')
            res.error(413)
          } else
            this.rawBody.push(chunk)
        })
        .once('end', next)
    }
  }

  /**
   * Decode multipart/form-data
   * @param {Buffer} chunk
   */
  bodyChunkDecode (chunk) {
    const files = this._files
    if (files.done)
      return
    chunk = files.chunk = files.chunk ? Buffer.concat([files.chunk, chunk]) : chunk
    const p = files.chunk.indexOf(files.boundary)
    if (p >= 0 && chunk.length - p >= 2) {
      if (files.last) {
        if (p > 0)
          files.last.write(chunk.subarray(0, p))
        files.last.srtream.close()
        delete files.last.srtream
        files.last = undefined
      }
      let pe = p + files.boundary.length
      if (chunk[pe] === '\r' && chunk[pe + 1] === '\n') {
        chunk = files.chunk = chunk.subarray(p)
        // next header
        pe = chunk.indexOf('\r\n\r\n')
        if (pe > 0) { // whole header
          const header = chunk.toString('utf8', files.boundary.length + 2, pe)
          chunk = chunk.subarray(pe + 4)
          const fileInfo = header.match(/content-disposition: ([^\r\n]+)/i)
          const contentType = header.match(/content-type: ([^\r\n;]+)/i)
          let fieldName, fileName
          if (fileInfo)
            fileInfo.replace(/(\w+)="?([^";]+)"?/, (_, n, v) => {
              if (n === 'name')
                fieldName = v
              if (n === 'filename')
                fileName = v
            })
          if (fileName) {
            let file
            do {
              file = path.resolve(path.join(files.uploadDir, crypto.randomBytes(16).toString('hex') + '.tmp'))
            } while (fs.existsSync(file))
            files.last = {
              name: fieldName,
              fileName: fileName,
              contentType: contentType && contentType[1],
              file: file,
              stream: fs.createWriteStream(file)
            }
            files.list.push(files.last)
          } else if (fieldName) {
            files.last = {
              name: fieldName,
              stream: {
                write (chunk) {
                  this._body[fieldName] = (this._body[fieldName] || '') + chunk.toString()
                },
                close () { }
              }
            }
          }
        }
      } else {
        files.chunk = undefined
        files.done = true
      }
    } else {
      if (chunk.length > 8096) {
        if (files.last)
          files.last.stream.write(chunk.subarray(0, files.boundary.length - 1))
        chunk = files.chunk = chunk.subarray(files.boundary.length - 1)
      }
    }
  }

  removeTempFiles () {
    if (this._files) {
      if (!this._files.done) {
        this.pause()
        this._files.resolve(new Error('Invalid request files usage'))
      }

      this._files.forEach(f => {
        if (f.stream)
          f.stream.close()
        if (f.file)
          fs.unlink(f.file, NOOP)
      })
      this._files = undefined
    }
  }
}

const commonCodes = { 404: 'Not found', 403: 'Access denied', 422: 'Invalid data', 'Not found': 404, 'Access denied': 403, 'Invalid data': 422, Failed: 422, OK: 200 }

export class ServerResponse extends http.ServerResponse {
  /**
   * Send error reponse
   * @param {string|Number|Error} error
   * @param {string} [text] 
   */
  error (error, text) {
    let code = error
    if (typeof error === 'string') {
      text = error
      code = commonCodes[error] || 500
    }
    if (error instanceof Error) {
      code = error.status || error.statusCode
      if (!code) {
        let name = (error.name || 'error').toLowerCase()
        text = error.message
        if (name === 'error') {
          const match = text.match(/^(\w+):\s*(.*)/)
          if (match) {
            name = match[1].toLowerCase()
            text = match[2]
          } else
            name = (text.match(/^\w+( \w+)?/) || ['error'])[0].toLowerCase()
        }
        if (name.includes('access') || name.includes('permission'))
          code = 403
        else if (name.includes('valid') || name.includes('case') || name.includes('param'))
          code = 422
        else if (name.includes('busy') || name.includes('timeout'))
          code = 408
      }
      code = code || commonCodes[text] || 500
      if (code === 500)
        console.error(error.stack || error)
    }
    try {
      if (code === 400 || code === 413)
        this.setHeader('Connection', 'close')
  
      this.statusCode = code || 200
      if (code < 200 || code === 204 || (code >= 300 && code <= 399))
        return this.send()
  
      if (this.isJson && (code < 300 || code >= 400))
        this.send({ success: false, error: text ?? (commonCodes[this.statusCode] || http.STATUS_CODES[this.statusCode]) })
      else
        this.send(text != null ? text : (this.statusCode + ' ' + (commonCodes[this.statusCode] || http.STATUS_CODES[this.statusCode])))
    } catch (e) {
      this.statusCode = 500
      this.send('Internal error')
      console.error(e)
    }
  }
  
  /**
   * sets Content-Type and sends response
   * @param {string|Buffer|Error|object} data
   */
  send (data) {
    if (!this.getHeader('Content-Type') && !(data instanceof Buffer)) {
      if (data instanceof Error)
        return this.error(data)
      if (this.isJson || typeof data === 'object') {
        data = JSON.stringify(typeof data === 'string' ? { message: data } : data)
        this.setHeader('Content-Type', 'application/json')
      } else {
        data = data.toString()
        if (data[0] === '{' || data[1] === '[')
          this.setHeader('Content-Type', 'application/json')
        else if (data[0] === '<' && (data.startsWith('<!DOCTYPE') || data.startsWith('<html')))
          this.setHeader('Content-Type', 'text/html')
        else
          this.setHeader('Content-Type', 'text/plain')
      }
    }
    this.setHeader('Content-Length', Buffer.byteLength(data || '', 'utf8'))
    if (this.headOnly)
      this.end()
    else
      this.end(data)
  }

  json (data) {
    this.isJson = true
    this.send(data)
  }

  /** 
   * send json response in form { success: false, error: err }
   * @param {number|string|Error} code - status code or error
   * @param {string} [text] - error message
   */
  jsonError (code, text) {
    this.isJson = true
    this.error(code, text)
  }
  
  /**
   * send json response in form { success: true, ... }
   * @param {Object|string} obj - object or string
   * @param {number} [code] - status code
   */
  jsonSuccess (obj, code) {
    this.isJson = true
    if (typeof obj === 'object') {
      obj = { success: true, ...obj }
    } else {
      if (typeof obj === 'string')
        obj = { success: true, message: obj }
      else
        obj = { success: true }
    }
    this.statusCode = code || 200
    this.send(obj)
  }

  /**
    * A function to redirect to a specified URL with an optional status code.
    * @param {number|string} code - The status code for the redirection, or the URL if no code is provided.
    * @param {string} url - The URL to redirect to.
    */
  redirect (code, url) {
    if (typeof code === 'string') {
      url = code
      code = 302
    }
    this.setHeader('Location', url)
    this.setHeader('Content-Length', 0)
    this.statusCode = code || 302
    this.end()
  }
}

const server = {}

/**
 * Controller for dynamic routes
 */
export class Controller {
  /**
   * @param {ServerRequest} req 
   * @param {ServerResponse} res 
   */
  constructor (req, res) {
    this.req = req
    this.body = req.body
    this.get = req.get
    this.params = req.params
    this.auth = req.auth
    this.res = res
    res.isJson = true
  }

  /** Generate routes for this controller */
  static routes () {
    const routes = []
    const prefix = Object.getOwnPropertyDescriptor(this, 'name').enumerable ? this.name + '/' : ''

    // iterate throught decorators
    Object.getOwnPropertyNames(this.prototype).forEach(key => {
      if (key === 'constructor' || key.startsWith('_'))
        return
      const func = this.prototype[key]
      if (typeof func !== 'function')
        return

      let url = this['url:' + key]
      let acl = this['acl:' + key] ?? this['acl']
      const user = this['user:' + key] ?? this['user']
      const role = this['role:' + key] ?? this['role']
      const group = this['group:' + key] ?? this['group']
      const model = this['model:' + key] ?? this['model']

      let method = ''
      if (!url)
        key = key.replaceAll('$', '/')
      if (!url && key.startsWith('/')) {
        method = '*'
        url = key
      }
      let keyMatch = !url && key.match(/^(all|get|put|post|patch|insert|update|modify|delete|websocket)[/_]?([\w_/-]*)$/i)
      if (keyMatch) {
        method = keyMatch[1]
        url = '/' + prefix + keyMatch[2]
      }
      keyMatch = !url && key.match(/^([*\w]+) (.+)$/)
      if (keyMatch) {
        method = keyMatch[1]
        url = keyMatch[2].startsWith('/') ? keyMatch[2] : ('/' + prefix + keyMatch[1])
      }
      keyMatch = !method && url?.match(/^([*\w]+) (.+)$/)
      if (keyMatch) {
        method = keyMatch[1]
        url = keyMatch[2].startsWith('/') ? keyMatch[2] : ('/' + prefix + keyMatch[2])
      }
      if (!method)
        return

      let autoAcl = method.toLowerCase()
      switch (autoAcl) {
        case '*':
          autoAcl = ''
          break
        case 'post':
          autoAcl = 'insert'
          break
        case 'put':
          autoAcl = 'update'
          break
        case 'patch':
          autoAcl = 'modify'
          break
      }
      method = method.toUpperCase()
      switch (method) {
        case '*':
          break
        case 'GET':
        case 'POST':
        case 'PUT':
        case 'PATCH':
        case 'DELETE':
        case 'WEBSOCKET':
            break
        case 'ALL':
          method = 'GET'
          break
        case 'INSERT':
          method = 'POST'
          break
        case 'UPDATE':
          method = 'PUT'
          break
        case 'MODIFY':
          method = 'PATCH'
          break
        default:
          throw new Error('Invalid url method for: ' + key)
      }
      if (user === undefined && group === undefined && role === undefined && acl === undefined)
        acl = prefix + autoAcl

      // add params if not available in url
      if (func.length && !url.includes(':')) {
        let args = []
        if (func.length === 1)
          url += '/:id'
        else {
          for (let i = 0; i < func.length; i++)
            url += '/:p' + i
        }
      }
      const list = [method + ' ' + url.replace(/\/\//g, '/')]
      if (acl)
        list.push('acl:' + acl)
      if (user)
        list.push('user:' + user)
      if (role)
        list.push('role:' + role)
      if (group)
        list.push('group:' + group)
      list.push((req, res) => {
        res.isJson = true
        const obj = new this(req, res)
        if (model) {
          req.model = obj.model = model instanceof Model ? model : Model.models[model]
          if (!obj.model)
            throw new ErrorInvalidData('model', model)
        }
        return obj[key].apply(obj, req.paramsList)
      })
      routes.push(list)
    })
    return routes
  }
}

export class Router {
  /** @param {MicroServer} server  */
  constructor (server) {
    this.server = server
    this._stack = []
    this._tree = {}
  }

  handler (req, res, next, method) {
    if (method)
      return !this._walkTree(this._tree[method], req, res, next) && next()
    const walk = () => {
      if (!this._walkTree(this._tree[req.method], req, res, next) &&
        !this._walkTree(this._tree['*'], req, res, next))
        next()
    }
    req.rewrite = url => {
      if (req.originalUrl)
        res.error(508)
      req.originalUrl = req.url
      req.url = url
      req.updateUrl()
      walk()
    }
    this._walkStack(this._stack, req, res, walk)
  }

  _walkStack (rstack, req, res, next) {
    let rnexti = 0
    const sendData = data => {
      if (!res.headersSent && data !== undefined) {
        if (data instanceof Buffer || typeof data === 'string' || data instanceof Error)
          res.send(data)
        else
          res.jsonSuccess(data)
      }
    }
    const rnext = () => {
      const cb = rstack[rnexti++]
      if (cb) {
        try {
          const p = cb(req, res, rnext)
          if (p instanceof Promise)
            p.catch(e => e).then(sendData)
          else
            sendData(p)
        } catch (e) {
          sendData(e)
        }
      } else
        return next()
    }
    return rnext()
  }
  
  _walkTree (item, req, res, next) {
    req.params = {}
    req.paramsList = []
    const rstack = []
    req.pathname.replace(/\/([^/]*)/g, (_, name) => {
      if (item) {
        if (item && item.hook)
          item.hook.forEach(i => rstack.push(i.bind(item)))
        if (!item.tree) { // last
          if (item.name) {
            req.params[item.name] += '/' + name
            req.paramsList[req.paramsList.length - 1] = req.params[item.name]
          }
        } else {
          item = item.last || item.tree[name] || item.param
          if (item && item.name) {
            req.params[item.name] = name
            req.paramsList.push(name)
          }
        }
      }
    })
    if (item && item.next) {
      req.router = item
      item.next.forEach(i => rstack.push(i))
    }
    if (!rstack.length)
      return
    this._walkStack(rstack, req, res, next)
    return true
  }  

  /**
   * 
   * @param {string} url 'METHOD /url' or '/url'
   * @param {string} key key name in tree structure
   * @param {*} values stack values
   * @returns 
   */
  _add (url, key, values) {
    if (key === 'next')
      console.debug('Route:', url, values)

    let method = url.match(/^(\w+) \//)
    if (method) {
      url = url.slice(method[0].length - 1)
      method = method[1]
    } else
      method = '*'

    values = values.map(i => this.server._bind(i))

    let item = this._tree[method]
    if (!item)
      item = this._tree[method] = { tree: {} }
    if (!url.startsWith('/')) {
      if (method === '*' && url === '*') {
        this._stack.push(...values)
        return this
      }
      url = '/' + url
    }
    url.replace(/\/(:?)([^/*]+)(\*?)/g, (_, param, name, last) => {
      if (last) {
        item.last = { name: name }
        item = item.last
      } else {
        if (!item.tree)
          throw new Error('Invalid route path')
        if (param) {
          item = item.param = item.param || { tree: {}, name: name }
        } else {
          let subitem = item.tree[name]
          if (!subitem)
            subitem = item.tree[name] = { tree: {} }
          item = subitem
        }
      }
    })
    if (!item[key])
      item[key] = []
    item[key].push(...values)
    return this
  }

  clear () {
    this._tree = {}
    this._stack = []
    return this
  }

  /**
   * @callback PluginInit
   * @param {Router} router
   * @param {...any} args
   */
  /** @typedef {{ plugin: PluginInit }} PluginModule */

  /**
   * Add middleware route.
   * Middlewares may return promises for res.jsonSuccess(...), throw errors for res.error(...), return string or {} for res.send(...)
   *
   * @signature add(plugin, ...args)
   * @param {Promise<PluginModule>} plugin async plugin module with `plugin` method
   * @param {...any} args
   * @return {Router} current router
   *
   * @signature add(plugin, ...args)
   * @param {PluginModule} plugin plugin module with `plugin` method
   * @param {...any} args
   * @return {Router} current router
   * 
   * @signature add(extension, ...args)
   * @param {string} extension microserver plugin name: static, proxy, websocket, vhost, localip, auth, hook
   * @param {...any} args
   * @return {Router} current router
   *
   * @signature add(method, url, ...middlewares)
   * @param {string} method http method (GET,POST,PUT,DELETE)
   * @param {string} url
   * @param {...string|function} middlewares
   * @return {Router} current router
   *
   * @signature add(url, ...middlewares)
   * @param {string} url - '/url' or 'METHOD /url'
   * @param {...string|function} middlewares
   * @return {Router} current router
   *
   * @signature add(routes)
   * @param {array[]} routes - routes: [ ['GET', '/test', ...], ['POST /test', ...], ['proxy', '/api', ...] ]
   * @return {Router} current router
   *
   * @signature add(keyRoutes)
   * @param {Object} routes - {'/url': middleware, '/url': [...middlewares], 'METHOD /url': [...middlewares]}
   * @return {Router} current router
   *
   * @signature add(url, [...routes])
   * @param {string} url - url
   * @param {any[]} routes - routes relative to root path ['GET /test', ...], ['proxy', '/api', ...]
   * @return {Router} current router
   */
  add (url, ...args) {
    if (!url)
      return this

    // add(middleware)
    if (typeof url === 'function' && args.length === 0) {
      // skip dupplicate middlewares by name
      if (!this.has(url))
        this._stack.push(url)
      else
        console.warn(new Warning('middleware allready exists').stack)
      return this.add()
    }

    // add(extension, ...args)
    if (MicroServerPlugins.has(url)) {
      MicroServerPlugins.get(url).apply(this, args)
      return this
    }

    // add(pluginmodule, ...args) may be promise
    if (url instanceof Promise || (typeof url === 'object' && typeof url.plugin === 'function')) {
      const err = new Error('Module must have method `plugin`') // for stacktrace
      this.server._init(() => Promise.resolve(url).then(mod => {
        if (typeof url !== 'object' || typeof mod.plugin !== 'function')
          throw err
        return mod.plugin(this.server, ...args)
      }))
      return this
    }

    // add({url: ...routes, ...}) convert to add('/', {url: ...routes, ...})
    // add([...routes]) convert to add('/', [...routes])
    // add(...middlewares) => add('/', ...middlewares)
    if (typeof url !== 'string')
      [url, args] = ['/', [url, ...args]]

    // add(method, url, ...middlewares) convert to add(url, ...middlewares)
    if (url === 'GET' || url === 'POST' || url === 'PUT' || url === 'PATCH' || url === 'DELETE') {
      if (typeof args[0] !== 'string' || !args[0].startsWith('/'))
        throw new Error('Url expected after method')
      url += ' ' + args.splice(0, 1)[0]
    }

    // add('/url', Controller)
    if (url.startsWith('/') && args.length === 1 && (typeof args[0] === 'function' || typeof args[0] === 'object') && args[0].routes)
      args[0] = typeof args[0].routes === 'function' ? args[0].routes() : args[0].routes

    // add('/url', {...routes}) convert to add('/url', [{...routes}])
    if (url.startsWith('/') && args.length === 1 && typeof args[0] === 'object' && !Array.isArray(args[0]))
      args[0] = [args[0]]

    // add('/url', [...routes])
    if (url.startsWith('/') && args.length === 1 && Array.isArray(args[0])) {
      args[0].forEach(item => {
        if (Array.isArray(item)) {
          // [methodUrl, ...middlewares]
          if (typeof item[0] === 'string' && item[0].match(/^([\w*]+ )?\//))
            return this.add(item[0].replace(/\//, (url === '/' ? '' : url) + '/'), ...item.slice(1))
          // [method, url, ...middlewares]
          if (typeof item[0] === 'string' && typeof item[1] === 'string' && item[1].startsWith('/'))
            return this.add(item[0], (url === '/' ? '' : url) + item[1], ...item.slice(2))
          // [...middlewares]
          return this.add(url, ...item)
        } else if (typeof item === 'object') {
          // { '/path': [...middlewares], 'METHOD /path': [...middlewares], '/url': middleware}
          for (const [subUrl, subArgs] of Object.entries(item)) {
            if (!subUrl.match(/^(\w+ )?\//))
              throw new Error('Url expected')
            this.add(subUrl.replace(/\//, (url === '/' ? '' : url) + '/'), ...(Array.isArray(subArgs) ? subArgs : [subArgs]))
          }
        } else
          throw new Error('Invalid param')
      })
      return
    }

    // add('METHOD /url', ...middlewares)
    return this._add(url, 'next', args.filter(o => o))
  }

  /**
   * Check if middleware allready added
   * @param {function} middleware 
   * @returns {boolean}
   */
  has (middleware) {
    return this._stack.includes(middleware) && (!middleware.name || !this._stack.find(f => f.name === middleware.name))
  }
}

export const MicroServerPlugins = new Map()

export class MicroServer extends EventEmitter {
  /** @description Create http MicroServer
   * returns:
   *    server.use(middleware)
   *    server.use(url, middleware)
   *    server.use(method, url, middleware)
   *    server.use(pluginName, options)
   *    server.router.clear()
   *    server.router.add(method, url, middleware)
   *    server.router.add(routes)
   *       [['GET', ....],
   *        ['POST', ...],
   *        ['PUT', ...],
   *        ['PATCH', ...],
   *        ['DELETE', ...],
   *        ['static', ...],
   *        ['proxy', ...],
   *        ['websocket', ...],
   *        ['hook:method', ...],
   *        <middleware>, ...]]
   *    server.router.add(url, routes)
   *    server.router.hook(method, url, middleware)
   *    server.get(url, ...)
   *    server.post(url, ...)
   *    server.put(url, ...)
   *    server.patch(url, ...)
   *    server.delete(url, ...)
   *    server.vhost(hostName, middleware)
   *    server.vhost(hostName)
   *    server.vhost(hostName, routes)
   *    server.vhost([hostName1, hostName1])
   *    server.vhost( { hostName:<routes|middleware>, ... } )
   *    server.vhosts[hostName]:Router
   *    server.static(url, root|options)
   *    server.proxy(url, remoteurl|options)
   *    server.websocket(url, cb)
   * @param {Object} options - server options
   * @param {string} options.listen - listen port(s) with optionsl host (Ex. 8080 or '0.0.0.0:8080,8180')
   * @param {string} options.root - server instance root path
   * @param {array} options.routes - routes list of: proxy, static, websocket, <middleware>, GET, POST, PUT, PATCH, DELETE
   * @param {Object.<string,Object>} options.vhosts - vhosts set of: { host:routes, ... }
   * @param {string} methods - allowed HTTP methods (default: 'OPTIONS,HEAD,GET,POST,PUT,PATCH,DELETE')
   * @param {boolean} options.localip - trust proxy headers
   * @param {boolean|string} options.cors - enable cors
   * @param {function} options.hook - middleware on request (before other middlwares)
   * @param {string} options.methods - allowed methods
   * @param {int} [options.maxBodySize=5000000] - max allowed body size in incomming request
   * @param {string} [options.uploadDir='./upload'] - temp files upload directory
   * @returns {MicroServer} - server instance
   */
  constructor (options = {}) {
    super()
    const wslist = {}
    this._wslist = wslist

    this._hook = options.hook
    let promise = Promise.resolve()
    this._init = (f, ...args) => {
      promise = promise.then(() => f.call(...args)).catch(e => console.log(e))
    }

    this.config = {maxBodySize: 5000000, ...options}
    this.router = new Router(this)
    this.root = path.normalize(options.root || process.cwd())

    if (typeof this._hook === 'function')
      this.use(this._hook)

    /** @type {Set<net.Server>} */
    this.servers = new Set()
    /** @type {Set<net.Socket>} */
    this.sockets = new Set()

    this.auth = new Auth()

    MicroServerPlugins.forEach((plugin, n) => {
      const v = options[n]
      if (v) {
        const arr = Array.isArray(v) ? v : [v]
        // console.debug('Plugin:', n, arr)
        arr.forEach(o => {
          if (o)
            this._init(plugin, this.router, o)
        })
      }
    })
    this.use(options.routes)

    this._init(() => {
      this.listen({
        tls: options.tls,
        listen: options.listen || 8080
      })
    })
  }

  /**
   * Add one time listener or call immediatelly for 'ready' 
   * @param {string} name 
   * @param {function} cb 
   */
  once (name, cb) {
    if (name === 'ready' && this._ready)
      cb()
    else
      super.once(name, cb)
    return this
  }

  /**
   * Add listener and call immediatelly for 'ready' 
   * @param {string} name 
   * @param {function} cb 
   */
  on (name, cb) {
    if (name === 'ready' && this._ready)
      cb()
    super.on(name, cb)
    return this
  }

  listen (options = {}) {
    const listen = (options.listen || this.config.listen || 0) + ''
    const handler = options.handler || this.handler.bind(this)

    const readFile = data => data && (data.indexOf('\n') > 0 ? data : fs.readFileSync(data))
    function tlsOptions() {
      return options.tls && {
        cert: readFile(options.tls.cert),
        key: readFile(options.tls.key),
        ca: readFile(options.tls.ca)
      }
    }
    function tlsOptionsReload(srv) {
      if (options.tls?.cert && options.tls.cert.indexOf('\n') < 0) {
        let debounce
        fs.watch(options.tls.cert, () => {
          clearTimeout(debounce)
          debounce = setTimeout(() => {
            debounce = undefined
            srv.setSecureContext(tlsOptions())
          }, 2000)
        })
      }
    }

    return new Promise(resolve => {
      let readyCount = 0
      this._ready = false
      const ready = srv => {
        if (srv)
          readyCount++
        if (readyCount >= this.servers.size) {
          if (!this._ready) {
            this._ready = true
            if (this.servers.size === 0)
              this.close()
            else
              this.emit('ready')
            resolve()
          }
        }
      }
      listen.replace(/((\w+):\/\/)?(([^:,]*):)?([^:,]+)/, (_, __, proto, ___, host, port) => {
        let srv
        switch (proto || options.type) {
          case 'tcp':
            srv = net.createServer(handler)
            break
          case 'tls':
            srv = tls.createServer(tlsOptions(), handler)
            tlsOptionsReload(srv)
            break
          case 'https':
            srv = https.createServer(tlsOptions(), handler)
            tlsOptionsReload(srv)
            break
          default:
            srv = http.createServer(handler)
            break
        }
  
        this.servers.add(srv)
        srv.type = (options.name || options.type || 'http').toUpperCase()
        if (port === 0) // skip listening if port is 0, usefull for integrated server
          ready(srv)
        else {
          srv.listen(port, host || '0.0.0.0', () => {
            const addr = srv.address()
            this.emit('listen', addr.port, addr.address, srv)
            ready(srv)
          })
        }
        srv.on('error', err => {
          this.servers.delete(srv)
          srv.close()
          ready()
          this.emit('error', err)
        })
        srv.on('connection', s => {
          this.sockets.add(s)
          s.once('close', () => this.sockets.delete(s))
        })
        ready()
      })
    })
  }

  _bind (fn) {
    if (typeof fn === 'string') {
      let name = fn
      let idx = name.indexOf(':')
      if (idx < 0 && name.includes('=')) {
        name = 'param:' + name
        idx = 5
      }
      if (idx >= 0) {
        const v = name.slice(idx + 1)
        const type = name.slice(0, idx)

        // predefined middlewares
        switch (type) {
          // redirect:302,https://redirect.to
          case 'redirect': {
            let redirect = v.split(','), code = parseInt(v[0])
            if (!code || code < 301 || code > 399)
              code = 302
            redirect = redirect[1] || v
            return (req, res) => res.redirect(code, redirect)
          }
          // error:422
          case 'error':
            return (req, res) => res.error(parseInt(v) || 422)
          // param:name=value
          case 'param': {
            idx = v.indexOf('=')
            if (idx > 0) {
              const prm = v.slice(0, idx), val = v.slice(idx + 1)
              return (req, res, next) => { req.param[prm] = val; return next() }
            }
            break
          }
          case 'model': {
            const model = v
            return (req, res) => {
              res.isJson = true
              req.param.model = model
              req.model = Model.models[model]
              if (!req.model) {
                console.error(`Data model ${req.param.model} not defined for request ${req.path}`)
                return res.error(422)
              }
              return req.model.middleware(req, res)
            }
          }
          // user:userid
          // role:user_role
          // group:user_groupid
          // acl:validacl
          case 'user':
          case 'role':
          case 'group':
          case 'acl':
            return (req, res, next) => {
              if (type === 'user' && v === req.user?.id)
                return next()
              if (type === 'acl') {
                req.params.acl = v
                if (req.auth && req.auth.acl(v))
                  return next()
              }
              if (type === 'role') {
                req.params.role = v
                if (req.user?.role === v)
                  return next()
              }
              if (type === 'group') {
                req.param.group = v
                if (req.user?.group === v)
                  return next()
              }
              const accept = req.headers.accept || ''
              if (req.auth?.options.redirect && req.method === 'GET' && !accept.includes('json') && (accept.includes('html') || accept.includes('*/*'))) {
                if (req.auth.options.redirect && req.url !== req.auth.options.redirect)
                  return res.redirect(302, req.auth.options.redirect)
                else if (req.auth.options.mode !== 'cookie') {
                  res.setHeader('WWW-Authenticate', `Basic realm="${req.auth.options.realm}"`)
                  return res.error(401)
                }
              }
              return res.error(403)
            }
        }
      }
      throw new Error('Invalid option: ' + name)
    }
    if (fn && typeof fn === 'object' && (fn.middleware || fn.handler))
      fn = (fn.middleware || fn.handler).bind(fn)
    if (typeof fn !== 'function')
      throw new Error('Invalid middleware: ' + toString(fn))
    return fn.bind(this)
  }

  /**
   * Add middleware, routes
   * @return {MicroServer} this instance
   */
  use (...args) {
    this.router.add(...args)
    return this
  }

  /**
   * Server handler for http.Server
   * @param {http.IncomingMessage} req
   * @param {http.ServerResponse} res
   */
  handler (req, res) {
    Object.setPrototypeOf(req, ServerRequest.prototype)
    Object.setPrototypeOf(res, ServerResponse.prototype)

    // limit input data size
    if (parseInt(req.headers['content-length'] || -1) > this.config.maxBodySize) {
      req.pause()
      res.error(413)
      return
    }

    req.updateUrl()
    res.statusCode = 200
    req.server = this
    res.server = this

    req.protocol = 'http'
    if (req.socket.ecrypted) {
      req.protocol = 'https'
      req.secure = true
    }

    req.rawBodySize = 0
    req.rawBody = []
    this.handlerInit(req, res, () => req.bodyChunkInit(res, () => this.handlerData(req, res, () => req.server.handlerLast(req, res))))
  }

  handlerInit (req, res, next) {
    let cors = this.config.cors
    if (cors && req.headers.origin) {
      if (cors === true)
        cors = '*'
      if (typeof cors === 'string')
        cors = { origin: cors, headers: 'Content-Type', credentials: true }

      if (cors.origin)  
        res.setHeader('Access-Control-Allow-Origin', cors.origin)
      if (cors.headers)
        res.setHeader('Access-Control-Allow-Headers', cors.headers)
      if (cors.credentials)
        res.setHeader('Access-Control-Allow-Credentials', 'true')
      if (cors.expose)
        res.setHeader('Access-Control-Expose-Headers', cors.expose)
      if (cors.maxAge)
        res.setHeader('Access-Control-Max-Age', cors.maxAge)
    }  

    if (req.method === 'HEAD') {
      req.method = 'GET'
      res.headOnly = true
    } else if (req.method === 'OPTIONS') {
      res.statusCode = 204
      res.setHeader('Allow', this.config.methods || 'GET, HEAD, POST, PUT, PATCH, DELETE')
      res.end()
      return
    }
    next()
  }

  handlerData(req, res, next) {
    if ((req.rawBodySize && req.rawBody[0] && (req.rawBody[0][0] === 91 || req.rawBody[0][0] === 123))
      || req.headers.accept?.includes?.('json') || req.headers['content-type']?.includes?.('json'))
      res.isJson = true
    req.server.router.handler(req, res, next)
  }

  handlerLast (req, res, next) {
    req.removeTempFiles()
    if (res.headersSent)
      return
    if (!next)
      next = () => res.error(404)
    return next()
  }

  /**
   * Close server instance
   */
  async close () {
    return new Promise(resolve => {
      let count = 0
      function done () {
        count--
        if (!count)
          resolve()
      }
      for (const s of this.servers) {
        count++
        s.once('close', done)
        s.close()
      }
      this.servers.clear()
      for (const s of this.sockets) {
        count++
        s.once('close', done)
        s.destroy()
      }
      this.sockets.clear()
    }).then(() => {
      this._ready = false
      this.emit('close')
    })
  }

  get (...args) {
    this.router.add('GET', ...args)
    return this
  }

  post (...args) {
    this.router.add('POST', ...args)
    return this
  }

  put (...args) {
    this.router.add('PUT', ...args)
    return this
  }

  patch (...args) {
    this.router.add('PATCH', ...args)
    return this
  }

  delete (...args) {
    this.router.add('DELETE', ...args)
    return this
  }
}

MicroServer.plugins = MicroServerPlugins

MicroServerPlugins.set('hook', (url, ...args) => {
  this._add(url, 'hook', args.filter(o => o))
})

/** @description Local IP middleware plugin
 * @param {Object} options local ip detection options
 * @param {string} options.trustProxy trust 'x-real-ip' header value
 * @returns {Function} middleware
 */
function pluginLocalIP (options) {
  function isLocal (ip) {
    return !!ip.match(/^(127\.|10\.|192\.168\.|172\.16\.|fe80|fc|fd|::)/)
  }
  this.server.use(function localip (req, res, next) {
    req.ip = res.socket.remoteAddress
    req.localip = isLocal(req.ip)
    const xip = req.headers['x-real-ip'] || req.headers['x-forwarded-for']
    if (xip) {
      if (options.trustProxy !== req.ip && (!Array.isArray(options.trustProxy) || !options.trustProxy.includes(req.ip)))
        return res.error(400)

      if (req.headers['x-forwarded-proto'] === 'https') {
        req.protocol = 'https'
        req.secure = true
      }
      req.ip = xip
      req.localip = isLocal(xip)  
    }
    return next()
  })
}
MicroServerPlugins.set('localip', pluginLocalIP)

/**
 * Virtual hosts plugin
 * @param {string} host - host
 * @param {function|string|array} cb - middleware or routing list
 * @return {MicroServer} this instance
 */
function pluginVhost (host, ...args) {
  this.server.vhosts = this.server.vhosts || {}
  // single vhost, routes...
  if (typeof (host) === 'string' && Array.isArray(args[0])) {
    const o = {}
    o[host] = args[0]
    host = o
  }
  // single vhost, single route
  if (typeof (url) === 'string' && (typeof args[0] === 'string' || typeof args[0] === 'function')) {
    const o = {}
    o[host] = args
    host = o
  }
  if (typeof (host) === 'object') {
    for (const n in host) {
      const router = new Router(this.server)
      router.add(host[n])
      n.split(',').forEach(n => {
        if (!this.server.vhosts[n])
          this.server.vhosts[n] = router
        else
          this.server.vhosts[n].add(host[n])
      })
    }
  } else
    throw new Error('Invalid parameters')

  this.server.use(function vhosts (req, res, next) {
    const host = req.headers.host
    if (this.server.vhost[host])
      this.server.vhost[host].handler(req, res, () => this.server.handlerLast(req, res, () => res.error(404)))
  })

  if (!this.server.vhost)
    this.server.vhost = function (...args) { this.use('vhost', ...args) }
}
MicroServerPlugins.set('vhost', pluginVhost)

// predefined mime types
const mimeTypes = {
  '.ico': 'image/x-icon',
  '.htm': 'text/html',
  '.html': 'text/html',
  '.txt': 'text/plain',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.css': 'text/css',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.mp3': 'audio/mpeg',
  '.svg': 'image/svg+xml',
  '.pdf': 'application/pdf',
  '.woff': 'application/x-font-woff',
  '.woff2': 'application/x-font-woff2',
  '.ttf': 'application/x-font-ttf'
}
const etagPre = crypto.randomBytes(4).toString('hex')

/** Static files plugin
 * @param {Object|string} root - static files root path and url='/' or options
 * @param {Object|string} options root path or options
 * @param {string} options.url - list of ignore subpath
 * @param {string} options.root - root path (relative)
 * @param {array|string} options.ignore - list of ignore subpath
 * @param {Object} options.handlers - set of handlers for file extensions Ex. { '.html': processor }
 * @returns {Function} middleware for static files
 */
function pluginStatic (root, options = {}) {
  if (!this.server.static) {
    this.server.static = function (...args) { this.use('static', ...args); return this }
    this.server.mimeTypes = mimeTypes
  }
  if (typeof root === 'object')
    options = Object.assign({}, root, options)
  else if (typeof root !== 'string')
    throw new Error('Invalid param')
  if (!options || typeof options === 'string')
    options = { root: options }
  root = path.resolve(options.root || root.replace(/^\//, '')) + path.sep
  const list = options.ignore ? Array.isArray(options.ignore) ? options.ignore : options.ignore.split(',') : [],
    ignore = []
  list.forEach(n => {
    if (n)
      ignore.push(path.normalize(path.join(root, n)) + path.sep)
  })

  function staticMiddleware (req, res, next) {
    if (req.method !== 'GET')
      next()

    let filename = path.normalize(path.join(root, (req.params && req.params.path) || req.pathname))
    if (!filename.startsWith(root)) // check root access
      return next()

    const firstch = path.basename(filename)[0]
    if (firstch === '.' || firstch === '_') // hidden file
      return next()

    if (filename.endsWith(path.sep))
      filename += 'index.html'

    const ext = path.extname(filename)
    const mimeType = mimeTypes[ext]
    if (!mimeType)
      return next()

    // check ignore access
    for (let i = 0; i < ignore.length; i++) {
      if (filename.startsWith(ignore[i]))
        return next()
    }

    fs.stat(filename, function (err, stats) {
      if (err || stats.isDirectory())
        return next()

      const handler = (req.handlers && req.handlers[ext]) ||
        (options.handlers && options.handlers[ext])
      if (handler) {
        req.script_file = filename
        return handler.call(this, req, res, next)
      }

      const etagMatch = req.headers['if-none-match']
      const etagTime = req.headers['if-modified-since']
      const etag = '"' + etagPre + stats.mtime.getTime().toString(32) + '"'

      res.setHeader('Content-Type', mimeType)
      if (options.lastModified !== false || req.params.lastModified)
        res.setHeader('Last-Modified', stats.mtime.toUTCString())
      if (options.etag !== false || req.params.etag)
        res.setHeader('Etag', etag)
      if (options.maxAge != null || req.params.maxAge)
        res.setHeader('Cache-Control', 'max-age=' + (options.maxAge || req.params.maxAge))

      if (res.headOnly) {
        res.setHeader('Content-Length', stats.size)
        return res.end()
      }

      if (etagMatch === etag || etagTime === stats.mtime.toUTCString()) {
        res.statusCode = 304
        return res.end()
      }

      res.setHeader('Content-Length', stats.size)
      fs.createReadStream(filename).pipe(res)
    })
  }
  this.server.use((options.url || '/').replace(/\/$/, '') + '/:path*', (req, res, next) => staticMiddleware(req, res, next))
}
MicroServerPlugins.set('static', pluginStatic)

/**
 * Websocket plugin
 * @param {string} url - url
 * @param {function|string} cb - middleware: function(websocket, req)
 */
function pluginWebSocket (url, ...middlewares) {
  const server = this.server
  if (typeof url !== 'string' || !middlewares.length)
    throw new Error('Invalid param')

  const cb = this.server._bind(middlewares[middlewares.length - 1])
  middlewares[middlewares.length - 1] = req => {
    server.wss.handleUpgrade(req, req.socket, req.head, ws => {
      server.wss.emit('connection', () => cb(req, ws))
    })
  }
  this.add('WEBSOCKET', url, ...middlewares)

  function upgradeHandler (req, socket, head) {
    const server = this
    req.server = server
    req.socket = socket // check if it is OK
    req.head = head
    const router = (server.vhosts && server.vhosts[req.headers.host]) || server.router
    const res = {
      headersSent: false,
      statusCode: 200,
      socket,
      server,
      write () {
        if (res.headersSent)
          throw new Error('Headers already sent')
        res.headersSent = true
        let code = parseInt(res.statusCode || 403)
        if (code < 400) {
          console.error('Invalid WS response')
          code = 500
        }
        socket.write('HTTP/1.1 ' + code + ' ' + http.STATUS_CODES[code] + '\r\n' +
          'Connection: Close\r\n' +
          'Content-Length: 0\r\n' +
          '\r\n', () => { socket.destroy() });
      },
      error (code) {
        res.statusCode = code || 403
        res.write()
      },
      end () {
        res.write()
      },
      send () {
        res.write()
      },
      setHeader () { }
    }

    const next = () => router.handler(req, res, () => res.error(404), 'WEBSOCKET')
    if (req.server._hook)
      return req.server._hook(req, res, next)
    return next()
  }
  if (!server.wss) {
    server.wss = {}
    import('./websocket-server.js').then(WebSocketServer => server.wss = new WebSocketServer({ noServer: true }))
    server.on('ready', () => {
      server.servers.forEach(srv => {
        if ((srv instanceof http.Server || srv instanceof https.Server) && srv.getListeners('upgrade').length === 0)
          srv.on('upgrade', upgradeHandler.bind(server))
      })
    })
    server.websocket = function (...args) { this.use('websocket', ...args); return this }
  }
}
MicroServerPlugins.set('websocket', pluginWebSocket)

const validHeaders = {
  authorization: true,
  accept: true,
  'accept-encoding': true,
  'accept-language': true,
  'cache-control': true,
  cookie: true,
  'content-type': true,
  'content-length': true,
  host: true,
  referer: true,
  'if-match': true,
  'if-none-match': true,
  'if-modified-since': true,
  'user-agent': true,
  date: true,
  range: true
}

/**
 * Add reverse proxy
 * @param {Object|string} url - url or options
 * @param {Object|string} [options] - remote url or options
 * @param {string} options.url - local url
 * @param {string} options.remote - remote url
 * @param {Object} [options.headers] - override headers
 * @param {string} [options.match] - allowed regex match for request url (optional)
 * @return {MicroServer} this instance
 */
function pluginProxy (url, options) {
  if (typeof options !== 'object')
    options = { remote: options }
  if (!options.remote)
    throw new Error('Invalid proxy usage')

  const remoteUrl = new URL(options.remote),
    match = options.match && new RegExp(options.match)

  if (!url.endsWith('/'))
    url += '/'
  this.add('*', url + ':path*', function proxy (req, res) {
    const reqOptions = { method: req.method, headers: {}, host: remoteUrl.hostname, port: remoteUrl.port, path: remoteUrl.pathname }, rawHeaders = req.rawHeaders
    let path = req.params.path
    if (path)
      path += (req.path.match(/\?.*/) || [''])[0]
    if (!path && match) {
      path = match(req.path)
      if (!path)
        return res.error(400)
      path = path.length > 1 ? path[1] : path[0]
    }
    if (!path)
      path = req.path
    if (path && path[0] !== '/')
      path = '/' + path
    reqOptions.path += path
    for (let i = 0; i < rawHeaders.length; i += 2) {
      const n = rawHeaders[i], nlow = n.toLowerCase()
      if (validHeaders[nlow] && nlow !== 'host')
        reqOptions.headers[n] = rawHeaders[i + 1]
    }
    if (options.headers)
      Object.assign(reqOptions.headers, options.headers)
    if (!reqOptions.headers.Host)
      reqOptions.headers.Host = url.hostname

    const conn = url.protocol === 'https:' ? https.request(reqOptions) : http.request(reqOptions)
    conn.on('response', response => {
      res.statusCode = response.statusCode
      for (let i = 0; i < response.rawHeaders.length; i += 2) {
        const n = response.rawHeaders[i], nlow = n.toLowerCase()
        if (nlow !== 'transfer-encoding' && n.nlow !== 'connection')
          res.setHeader(n, res.rawHeaders[i + 1])
      }
      response.on('data', chunk => {
        res.write(chunk)
      })
      response.on('end', () => {
        res.end()
      })
    })
    conn.on('error', () => res.error(502))

    // Content-Length must be allready defined
    if (req.rawBody.length) {
      const postStream = new stream.Readable()
      req.rawBody.forEach(chunk => {
        postStream.push(chunk)
      })
      postStream.push(null)
      postStream.pipe(res)
    } else
      conn.end()
  })
  if (!this.server.proxy)
    this.server.proxy = (...args) => this.server.use('proxy', ...args)
}
pluginProxy.validHeaders = validHeaders
MicroServerPlugins.set('proxy', pluginProxy)

// Auth routines
const hashFnv32a = function (str) {
  var i, l, hval = 0x811c9dc5
  for (i = 0, l = str.length; i < l; i++) {
    hval ^= str.charCodeAt(i)
    hval += (hval << 1) + (hval << 4) + (hval << 7) + (hval << 8) + (hval << 24)
  }
  return ('0000000' + (hval >>> 0).toString(16)).slice(-8)
}

export class Auth {
  /**
   * @param {ServerRequest} req 
   * @param {ServerResponse} res 
   * @param {*} options 
   */
  constructor (req, res, options = {}) {
    this.req = req
    this.res = res
    this.options = options
    if (!options.token)
      options.token = defaultToken
    if (options.token.length !== 32)
      options.token = crypto.createHash('sha256').update(options.token).digest()
    this.users = typeof options.users === 'object' ? async function (usrid, psw) {
      const usr = options.users[usrid]
      if (usr && (psw === undefined || this.checkPassword(usrid, psw, usr.password)))
        return usr
    } : (typeof options.users === 'function' && options.users)
    this.handler = this.handler.bind(this)
  }

  decode (data) {
    data = data.replace(/-/g, '+').replace(/\./g, '/')
    var iv = Buffer.from(data.slice(0, 22), 'base64')
    data = data.slice(22)

    try {
      var decipher = crypto.createDecipheriv('aes-256-cbc', this.options.token, iv)
      var dec = decipher.update(data, 'base64', 'utf8')
      dec += decipher.final('utf8')

      dec = dec.match(/^((.*);([0-9a-f]{8});\s*)([0-9a-f]{8})$/)
      if (dec && hashFnv32a(dec[1]) === dec[4])
        return [dec[2], parseInt(dec[3], 16) + 946681200 - Math.floor(new Date() / 1000)]
    } catch (e) {
    }
    return []
  }

  encode (data, expire) {
    expire = ('0000000' + (Math.floor(new Date() / 1000) - 946681200 + (expire || this.options.expire)).toString(16)).slice(-8)
    data = data + ';' + expire + ';'
    data = data.padEnd(((data.length + 8 + 15) & 0xFFF0) - 8, ' ')
    data = data + hashFnv32a(data)

    var iv = crypto.randomBytes(16)
    var cipher = crypto.createCipheriv('aes-256-cbc', this.options.token, iv)
    var encrypted =
      iv.toString('base64').slice(0, 22) +
      cipher.update(data, 'utf8', 'base64') +
      cipher.final('base64')
    encrypted = encrypted.replace(/==?/, '').replace(/\//g, '.').replace(/\+/g, '-')
    return encrypted
  }

  /**
   * Validate cookie and retrieve user object
   */
  async init () {
    const { req, res, options } = this
    const authorization = req.headers.authorization || '';
    if (authorization.startsWith('Basic ')) {
      let usr = options.cache.get(authorization)
      if (usr)
        req.user = usr.data
      else {
        const usrpsw = Buffer.from(authorization.slice(6), 'base64').toString('utf-8'),
          pos = usrpsw.indexOf(':'), username = usrpsw.slice(0, pos), psw = usrpsw.slice(pos + 1)
        if (username && psw)
          req.user = await this.users(username, psw)
        if (req.user) // 1 hour to expire in cache
          options.cache.set(authorization, { data: req.user, time: new Date(new Date().getTime() + 3600000) })
        else
          return res.error(401)
      }
      return
    }

    const cookie = req.headers.cookie, cookies = cookie ? cookie.split(/;\s+/g) : []
    const sid = cookies.find(s => s.startsWith('token='))
    let token = ''
    if (authorization.startsWith('Bearer '))
      token = authorization.slice(7)

    if (sid)
      token = sid.slice(sid.indexOf('=') + 1)

    if (!token)
      token = req.get.token

    if (token) {
      const now = new Date(), cache = options.cache
      let usr, expire
      if (options.cacheCleanup > now) {
        options.cacheCleanup = new Date(now.getTime() + 600000)
        setTimeout(() => cache.forEach((k, v) => { if (v.time < now) cache.delete(k) }), 1)
      }

      // check in cache
      this.tokenId = token
      usr = options.cache.get(token)
      if (usr && usr.time > now)
        [req.user, expire] = [usr.data, Math.floor((usr.time - now) / 1000)]
      else {
        [usr, expire] = this.decode(token)
        if (!usr) {
          this.logout()
          return
        }
        if (usr.startsWith('{')) {
          try {
            usr = JSON.parse(usr)
            req.user = usr
          } catch (e) { usr = undefined }
        } else if (this.users) {
          req.user = await this.users(usr)
          if (!req.user) {
            this.logout()
            return
          }
        }
        if (req.user)
          options.cache.set(token, { data: req.user, time: expire })
      }
      // renew
      if (req.user && expire < options.expire / 2)
        await this.login(req.user)
    }
  }

  /**
   * Check acl over authenticated user with: `id`, `group/*`, `*`
   * @param {string} id - to authenticate: `id`, `group/id`, `model/action`, comma separated best: true => false => def 
   * @param {boolean} [def=true] - default access
   */
  acl (id, def = true) {
    if (!this.req.user)
      return false
    if (id === 'auth')
      return true
    const reqAcl = this.req.user.acl || this.options.acl
    if (!reqAcl)
      return def

    // this points to req
    let access
    id = (id || '').split(',')
    id.forEach(id => access ||= reqAcl[id])
    if (access !== undefined)
      return access
    id.forEach(id => {
      const p = id.lastIndexOf('/')
      if (p > 0)
        access ||= reqAcl[id.slice(p + 1) + '*']
    })
    if (access === undefined)
      access = reqAcl['*']
    return access === undefined ? def : access
  }

  /**
     * Authenticate user and setup cookie
     * @param {string|object} usr - user id used with options.users to retrieve user object. User object must contain `id` and `acl` object (Ex. usr = {id:'usr', acl:{'users/*':true}})
     * @param {string} [psw] - user password (if used for user authentication with options.users)
     * @param {number} [expire] - expire time in seconds (default options.expire)
     */
  async token (usr, psw, expire) {
    if (typeof usr === 'string' && this.users)
      usr = await this.users(usr, psw)
    if (usr && (usr.id || usr._id)) {
      const data = this.users ? (usr.id || usr._id) : JSON.stringify(usr)
      return this.encode(data, expire || this.options.expire)
    }
  }

  /**
   * Authenticate user and setup cookie
   * @param {string|object} usr - user id used with options.users to retrieve user object. User object must contain `id` and `acl` object (Ex. usr = {id:'usr', acl:{'users/*':true}})
   * @param {string} [psw] - user password (if used for user authentication with options.users)
   * @param {number} [expire] - expire time in seconds (default options.expire)
   */
  async login (usr, psw, expire) {
    if (typeof usr === 'string' && this.users)
      usr = await this.users(usr, psw)
    if (usr && this.options.mode === 'cookie') {
      expire = expire || this.options.expire
      const expireTime = new Date(new Date().getTime() + expire * 1000)
      const token = await this.token(usr, psw, expire)
      if (token) {
        if (this.tokenId)
          this.options.cache.delete(this.tokenId)
        this.tokenId = token
        this.res.setHeader('set-cookie', 'token=' + token + '; expires=' + expireTime.toUTCString() + '; Path=' + this.req.baseUrl)
        this.options.cache.set(token, { data: usr, time: expireTime })
      }
    }
    return usr
  }

  /**
   * Logout logged in user
   */
  logout () {
    if (this.tokenId)
      this.options.cache.delete(this.tokenId)
    if (this.options.mode === 'cookie')
      this.res.setHeader('set-cookie', 'token=; expires=' + new Date('2000-01-01').toUTCString() + '; Path=' + this.req.baseUrl)
    else {
      if (this.req.headers.authentication) {
        this.res.setHeader('Set-Cookie', 'token=')
        this.res.error(401)
      }
    }
    this.req.user = undefined
  }

  /**
   * Get hashed string from user and password
   * @param {string} usr - user id
   * @param {string} psw - password
   * @param {string} salt - password salt (prefix for randomness)
   */
  password (usr, psw, salt) {
    return Auth.password(usr, psw, salt)
  }

  /**
   * Get hashed string from user and password
   * @param {string} usr - user id
   * @param {string} psw - password
   * @param {string} salt - password salt (prefix for randomness)
   */
  static password (usr, psw, salt) {
    if (usr)
      psw = crypto.createHash('sha512').update(usr + '|' + psw).digest('hex')
    if (salt) {
      salt = salt === '*' ? crypto.randomBytes(32).toString('hex') : salt.slice(0, 64)
      psw = salt + crypto.createHash('sha512').update(psw + salt).digest('hex')
    }
    return psw
  }

  /**
     * Check hash/plain password
     * @param {string} usr - user id
     * @param {string} psw - password
     * @param {string} salt - password salt (prefix for randomness)
     */
  checkPassword (usr, psw, storedPsw) {
    return Auth.checkPassword(usr, psw, storedPsw)
  }

  /**
   * Check hash/plain password
   * @param {string} usr - user id
   * @param {string} psw - password
   * @param {string} salt - password salt (prefix for randomness)
   */
  static checkPassword (usr, psw, storedPsw) {
    if (usr && storedPsw) {
      let success = false
      if (storedPsw.length === 128) { // salted hash
        // rnd-salted-hash == salted-hash
        if (psw.length === 128)
          success = psw === this.password('', storedPsw, psw)
        else if (psw.length > storedPsw.length)
          success = psw === this.password('', storedPsw, psw.slice(0, psw.length - storedPsw.length))
      } else if (storedPsw.length === 64) { // hash
        // plain == hash
        if (psw.length < 64)
          success = this.password(usr, psw) === storedPsw
        // rnd-hash == hash
        else if (psw.length === 128)
          sucess = psw === this.password(usr, storedPsw, psw)
      } else { // plain
        // plain == plain
        if (psw.length < 64)
          success = psw === storedPsw
        // rnd-hash == plain
        else if (psw.length === 128)
          sucess = psw === this.password(usr, this.password(usr, storedPsw), psw)
      }
      return success
    }
  }

  /**
   * Clear user cache if users setting where changed
   */
  clearCache () {
    this.options.cache.clear()
  }

  handler (req, res, next) {
    req.auth = new Auth(req, res, this.options)
    req.auth.init()
      .then(() => {
        if (!res.headersSent)
          next()
      })
  }
}

/*
// Client login implementation
async function login (username, password) {
  function hex (b) { return Array.from(Uint8Array.from(b)).map(b => b.toString(16).padStart(2, "0")).join("") }
  async function hash (data) { return hex(await crypto.subtle.digest('sha-512', new TextEncoder().encode(data)))}
  const rnd = hex(crypto.getRandomValues(new Int8Array(32)))
  return rnd + await hash(await hash(username + '|' + password) + rnd)
}
 
// Server login implementation
// password should be stored with `req.auth.password(req, user, password)` but may be in plain form too
 
server.use('auth', {
  users: {
    testuser: {
      acl: {
        'user/update': true,
        'messages/*': true,
      },
      password: <hash-password>
    },
    admin: {
      acl: {
        'user/*': true,
        'messages/*': true,
      },
      password: <hash-password>
    }
  }
})
//or
server.use('auth', {
  async users (usr, psw) {
    const obj = await db.getUser(usr)
    if (!obj.disabled && this.checkPassword(usr, psw, obj.password)) {
      const {password, ...res} = obj // remove password field
      return res
    }
  }
})
 
async function loginMiddleware(req, res) {
  const user = await req.auth.login(req.body.username || '', req.body.password || '')
  if (user)
    res.jsonSuccess(user)
  else
    res.jsonError('Access denied')
}
 
// More secure way is to store salted hashes on server `req.auth.password(user, password, '*')`
// and corespondingly 1 extra step is needed in athentication to retrieve salt from passwod hash `password.slice(0, 64)`
// client function will be:
async function login (username, password, salt) {
  function hex (b) { return Array.from(Uint8Array.from(b)).map(b => b.toString(16).padStart(2, "0")).join("") }
  async function hash (data) { return hex(await crypto.subtle.digest('sha-512', new TextEncoder().encode(data)))}
  const rnd = hex(crypto.getRandomValues(new Int8Array(32)))
  return rnd + await hash(await hash(salt + await hash(await hash(username + '|' + password) + salt)) + rnd)
} 
*/

const defaultToken = 'wx)>:ZUqVc+E,u0EmkPz%ZW@TFDY^3vm'

/** @description Auth functionality
 * @param {Object} options
 * @param {string} options.token - token for cookie encrytion
 * @param {number} options.expire - cookie expire time in seconds
 * @param {Object} options.acl - default acl if not authenticated
 * @param {function(usr,psw)|object} [options.users] - `function(usr,psw?)` to retrieve user object or users object in format users = {'userid':{acl:{...}, password:'hash'}}
 * @param {Object} [users] - list of user acl's
 */
function pluginAuth (options = {}) {
  const authOptions = {
    mode: 'cookie',
    token: defaultToken,
    expire: 24 * 60 * 60,
    default: { '*': false },
    ...this.server.auth?.options,
    ...options,
    cache: new Map(),
    cacheCleanup: new Date()
  }

  if (authOptions.token === defaultToken)
    console.warn('Default token in auth plugin')

  this.server.auth = new Auth(undefined, undefined, authOptions)
  if (!this.server.router.has(this.server.auth.handler))
    this.server.router.add(this.server.auth.handler)
}
MicroServerPlugins.set('auth', pluginAuth)

export function create (options) { return new MicroServer(options) }

/**
 * @typedef FileStoreOptions
 * @prop {string} [dir='data'] Base directory
 * @prop {number} [cacheTimeout=2000] Cache timeout in milliseconds
 * @prop {number} [cacheItems=10] Max number of cached items
 * @prop {number} [debounceTimeout=1000] Debounce timeout in milliseconds for autosave
 */

/** JSON File store */
export class FileStore {
  /**
   * @param {FileStoreOptions} options
   */
  constructor (options) {
    this.cache = {}
    this._promise = Promise.resolve()
    this.dir = 'data'
    this.cacheTimeout = 2000
    this.cacheItems = 10
    this.debounceTimeout = 1000
    this.iter = 0
    Object.assign(this, options || {})
  }

  /** cleanup cache */
  cleanup () {
    if (this.iter > this.cacheItems) {
      this.iter = 0
      const now = new Date().getTime()
      const keys = Object.keys(this.cache)
      if (keys.length > this.cacheItems) {
        keys.forEach(n => {
          if (now - this.cache[n].atime > this.cacheTimeout)
            delete this.cache[n]
        })
      }
    }
  }

  _lock (cb) {
    if (!this._promise.count) {
      let r
      this._promise = new Promise(resolve => r = resolve)
      this._promise.resolve = r
      this._promise.count = 0
    }
    this._promise.count++
    if (cb) {
      const lock = this._promise
      return new Promise(resolve => resolve(cb())).finally(() => this._unlock(lock))
    }
    return this._promise
  }

  _unlock (promise) {
    if (!promise || this._promise === promise) {
      if ((--promise.count) <= 0)
        promise.resolve()
      return true
    }
  }

  ready () {
    return this._promise
  }

  async close () {
    await this.ready()
    this.iter = 0
    this.cache = {}
  }

  /**
   * load json file data
   * 
   * @aparam {string} name
   * @aparam {boolean} [autosave=false]
   * @return {Promise<Object>}
   */
  async load (name, autosave) {
    return this._lock(async () =>  {
      const now = new Date().getTime(), item = this.cache[name]
      if (!item || now - item.atime > this.cacheTimeout) {
        try {
          const stat = await fs.promises.lstat(path.join(this.dir, name))
          if (item?.mtime !== stat.mtime) {
            let data = await fs.promises.readFile(path.join(this.dir, name), 'utf8')
            this.iter++
            this.cleanup()
            data = JSON.parse(data)
            if (autosave)
              data = this.observe(data, () => this.save(name, data))
            this.cache[name] = {
              atime: new Date(),
              mtime: stat.mtime,
              data: data
            }
            return data
          }
        } catch {
          delete this.cache[name]
        }
      }
      return item?.data
    })
  }

  /**
   * save data
   * 
   * @aparam {string} name
   * @aparam {Object} data
   * @return {Promise<void>}
   */
  async save (name, data) {
    return this._lock(async () =>  {
      this.iter++
      this.cleanup()
      this.cache[name] = {
        atime: new Date().getTime(),
        mtime: new Date().getTime(),
        data: data
      }
      try {
        await fs.promises.writeFile(path.join(this.dir, name), JSON.stringify(data))
      } catch {
      }
    })
  }

  /**
   * load all files in directory
   * 
   * @aparam {string} name
   * @aparam {boolean} [autosave=false]
   * @return {Promise<Object>}
   */
  async all (name, autosave) {
    return this._lock(async () =>  {
      const files = await fs.promises.readdir(name ? path.join(this.dir, name) : this.dir)
      const res = {}
      await Promise.all(files.map(file => 
        (file.startsWith('.') && !file.startsWith('_') && !file.startsWith('$')) &&
          this.load(name ? name + '/' + file : file, autosave)
            .then(data => {res[file] = data})
      ))
      return res
    })
  }

  /**
   * delete data file
   * 
   * @aparam {string} name
   * @return {Promise<void>}
   */
  async delete (name) {
    return this._lock(async () =>  {
      delete this.cache[name]
      try {
        await fs.promises.unlink(path.join(this.dir, name))
      } catch {
      }
    })
  }

  /**
   * Observe data object
   * @param {Object} data
   * @param {(data: Object, key: string, value: any) => void} cb
   * @return {Object}
   */
  observe (data, cb) {
    let lock
    const changed = (target, key, value) => {
      if (!lock) {
        lock = this._lock()
        setTimeout(() => {
          const _lock = lock
          lock = undefined
          if (this._unlock(_lock))
            cb.call(data, target, key, value)
        }, this.debounceTimeout)
      }
    }
    const handler = {
      get(target, key) {
        if (typeof target[key] === 'object' && target[key] !== null)
          return new Proxy(target[key], handler)
        return target[key]
      },
      set(target, key, value) {
        if (target[key] === value)
          return true
        if (value && typeof value === 'object')
          value = {...value}
        target[key] = value
        changed(target, key, value)
        return true
      },
      deleteProperty(target, key) {
        delete target[key]
        changed(target, key, undefined)
        return true
      }
    }
    return new Proxy(data, handler)
  }
}


export class ErrorAccessDenied extends Error {
  constructor (msg) {
    super(msg || 'Access denied')
    this.name = 'ErrorAccessDenied'
  }
}

export class ErrorInvalidData extends Error {
  constructor (type, name) {
    super(name ? `Invalid ${type}: ${name}` : `Invalid ${type}`)
    this.name = 'ErrorInvalidData'
  }
}

let globalObjectId = crypto.randomBytes(8)
function newObjectId() {
  for (let i = 7; i >= 0; i--)
    if (++globalObjectId[i] < 256)
      break
  return (new Date().getTime() / 1000 | 0).toString(16) + globalObjectId.toString('hex')
}

/**
 * @typedef {Object} ModelCallbackOptions
 * @property {string} name - field name
 * @property {FieldDescription} field - field description
 * @property {Model} model - model
 * @property {Object} [user] - request user
 * @property {Object} [params] - request params
 * @property {boolean} [insert=false] - prepare for insert
 * @property {boolean} [readOnly=false] - prepare for get
 * @property {boolean} [validate=true] - don't validate value
 * @property {boolean} [default=true] - don't fill default value
 */

/**
 * @typedef {Object} ModelOptions
 * @property {Object} user - request user
 * @property {Object} params - request params
 * @property {boolean} [insert=false] - prepare for insert
 * @property {boolean} [readOnly=false] - prepare for get
 * @property {boolean} [validate=true] - don't validate values
 * @property {boolean} [default=true] - don't fill default values
 */

/**
 * @typedef {(options: ModelCallbackOptions)=>any} ModelCallbackFunc
 */

/**
 * Model field description
 * @typedef {Object} FieldDescription
 * @property {string} type
 * @property {boolean} required
 * @property {boolean} filter
 * @property {boolean|string|ModelCallbackFunc} canRead - if field can be read, may use placeholders (ex. `${user.acl.insert}`)
 * @property {boolean|string|ModelCallbackFunc} canWrite - if field can be written, may use placeholders (ex. `${user.acl.insert}`)
 * @property {number|string|ModelCallbackFunc} default - default value, may use placeholders (ex. `${now}`)
 * @property {(value: any, options: ModelCallbackOptions) => any} [validate] - validate function
 * @property {Array} [enum] - must be one of possible values
 * @property {number|string} [minimum] - minimum value
 * @property {number|string} [maximum] - maximum value
 */

export class Model {
  static models = {}

  /**
   * Define model
   * @param {string|Object.<string, FieldDescription>} name
   * @param {Object.<string, FieldDescription>} model
   * @param {Object} options
   * @param {string} options.name
   * @param {MicroCollection} options.collection
   * @return {Model}
   */
  static define(name, model, options) {
    if (typeof name === 'object') {
      options = model || {}
      model = name
      name = options.name
    }
    return new Model(model, { name, ...options})
  }

  /**
   * Create model acording to description
   * @param {Object.<string, FieldDescription>} model
   * @param {Object} options
   * @param {string} options.name
   * @param {MicroCollection} options.collection
   */
  constructor (model, options = {}) {
    this.model = model
    if (typeof options === 'string')
      options = { name: options }
    this.options = options || {}
    this.name = options.name || this.constructor.name
    this.collection = options.collection
    if (options.name)
      Model.models[options.name] = this
    this.handler = this.handler.bind(this)

    for (const n in this.model) {
      let field = this.model[n]
      if (typeof field !== 'object')
        field = this.model[n] = {type: field}
      if (Array.isArray(field.type)) {
        field.array = true
        field.type = field.type[0] || 'any'
      }
      if (typeof field.type === 'function')
        field.type = field.type.name
      if (field.type && !(field.type instanceof Model))
        switch (field.type) {
          case "ObjectID":
          case "ObjectId":
            field.type = 'ObjectId'
            break
          case 'String':
          case 'string':
            field.type = 'string'
            break
          case 'Number':
          case 'number':
            field.type = 'number'
            break
          case 'Int':
          case 'Integer':
          case 'int':
            field.type = 'int'
            break
          case "JSON":
          case "Object":
          case "object":
            field.type = 'object'
            break
          case 'Boolean':
          case 'boolean':
            field.type = 'boolean'
            break
          case 'Array':
          case 'array':
            field.array = true
            field.type = 'any'
            break
          case 'Date':
          case 'date':
            field.type = 'date'
            break
          case '*':
          case 'any':
            field.type = 'any'
            break
          default:
            throw new Error(`Invalid field type: ${field.type}`)
        }
      field.canWrite = this._fieldFunction(field.canWrite, typeof field.canWrite === 'string' && field.canWrite.startsWith('$') ? false : true)
      field.canRead = this._fieldFunction(field.canRead, typeof field.canRead === 'string' && field.canRead.startsWith('$') ? false : true)
      if (field.default !== undefined) {
        const def = field.default
        if (typeof def === 'function' && (def.name === 'ObjectId' || def.name === 'Date'))
          field.default = () => new def.constructor()
        else if (typeof def !== 'function')
          field.default = this._fieldFunction(def)
      }
    }
  }

  /**
   * Validate data over model
   * @param {Object} data - input data
   * @param {ModelOptions} [options] - validate options
   * @return {Object} validated data
   */
  validate (data, options) {
    options = options || {}
    if (options.validate === false)
      return data
    const res = {}
    for (const n in this.model) {
      const field = this.model[n]
      const canWrite = field.canWrite(options), canRead = field.canRead(options)
      if (options.readOnly) {
        if (canRead === false || !field.type)
          continue
        if (data[n] !== undefined) {
          res[n] = data[n]
          continue
        }
        else if (!field.required)
          continue
      }
      let v = canWrite === false ? undefined : data[n]
      if (v === undefined) {
        if (options.default !== false && field.default)
          v = field.default.length ? field.default({...options, field, name: n, model: this}) : field.default()
        if (v !== undefined) {
          res[n] = v
          continue
        }
        if (field.required && canWrite !== false && (!options.insert || n !== '_id'))
          throw new ErrorInvalidData('field', n)
        continue
      }
      if (options.readOnly) {
        res[n] = v
        continue
      }
      if (!field.type)
        continue
      if (field.array) {
        if (!Array.isArray(v))
          throw new ErrorInvalidData('field', n)
        res[n] = v.map(v => this._validateField(n, v, field, options))
      } else
        res[n] = this._validateField(n, v, field, options)
    }
    return res
  }

  _fieldFunction(value, def) {
    if (typeof value === 'string' && value.startsWith('${') && value.endsWith('}')) {
      const names = value.slice(2, -1).split('.')
      if (names.length === 1) {
        const n = names[0]
        if (n === 'now' || n === 'Date')
          return () => new Date()
        if (n === 'ObjectId')
          return () => newObjectId()
        return options => options[n] ?? def
      }
      return options => names.reduce((p, n) => p = typeof p === 'object' ? p[n] : undefined, options) ?? def
    }
    if (value === undefined)
      return () => def
    return () => value
  }

  _validateField (name, value, field, options) {
    if (value === undefined || value === null) {
      if (field.required && (!options.insert || name !== '_id'))
        throw new ErrorInvalidData('field', name)
      return null
    }
    switch (field.type) {
      case "ObjectId":
        if ((typeof value === 'object' && value.constructor.name === 'ObjectId') || typeof value === 'string') {
          value = value.valueOf()
          break
        }
        throw new ErrorInvalidData('field', name)
      case "date":
        if (value instanceof Date)
          break
        if (typeof value === 'string' || typeof value === 'number') {
          value = new Date(value)
          if (!isNaN(value.getTime()))
            break
        }
        throw new ErrorInvalidData('field', name)
      case "string":
        value = value.toString()
        break
      case "number":
        if (typeof v !== 'number')
          value = parseFloat(value)
        if (!isNaN(value))
          break
        throw new ErrorInvalidData('field', name)
      case "int":
        value = parseInt(value)
        if (!isNaN(value))
          break
        throw new ErrorInvalidData('field', name)
      case "object":
        if (typeof value === 'object' && !Array.isArray(value))
          break
        throw new ErrorInvalidData('field', name)
      case "any":
        break
      default:
        if (field.type instanceof Model)
          value = field.type.validate(value, options)
        else
          throw new ErrorInvalidData('field', name)
        break
    }
    if (typeof field.validate === 'function') {
      const v = field.validate(value, {...options, field, name, model: this})
      if (v === false)
        throw new ErrorInvalidData('field', name)
      return v === true ? v : field.type === 'boolean' ? !!value : value
    }
    if (field.minimum && value < field.minimum)
      throw new ErrorInvalidData('field', name)
    if (field.maximum && value > field.maximum)
      throw new ErrorInvalidData('field', name)
    if (field.length && value.length !== field.length)
      throw new ErrorInvalidData('field', name)
    if (field.format === 'email' && (typeof value !== 'string' || !value.match(/^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/)))
      throw new ErrorInvalidData('field', name)
    if (field.format === 'url' && (typeof value !== 'string' || !value.match(/^https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)$/)))
      throw new ErrorInvalidData('field', name)
    if (field.pattern && !field.pattern.test(value))
      throw new ErrorInvalidData('field', name)
    if (field.enum && !field.enum.includes(value))
      throw new ErrorInvalidData('field', name)
    return value
  }

  /**
   * Generate filter for data queries
   * @param {Object} data 
   * @param {ModelOptions} [options]
   * @param {Object} [options.filter] - extra filter
   * @returns {Object} - filter object
   */
  getFilter (data, options) {
    const res = {}
    if (data._id)
      res._id = data._id
    for (const name in this.model) {
      if (!(name in res)) {
        const field = this.model[name]
        if ((!options.required && name in data) || (field.required && field.default)) {
          if (field.required && field.default && (!(name in data) || field.canWrite(options) === false))
            res[name] = options?.default !== false ? field.default.length ? field.default({...options, field, name, model: this}) : field.default() : data[name]
          else if (name in data)
            res[name] = options?.validate !== false ? this._validateField(name, data[name], field, options) : data[name]
        }
      }
    }
    if (typeof options?.filter === 'object')
      for (const name in filter) {
        if (name !== '_id' && name in this.model && !res[name])
          res[name] = filter[name]
      }
    return res
  }

  /**
   * Collect data
   * @param {Object} data - query data
   * @param {ModelOptions} options
   * @returns 
   */
  async findOne (data, options) {
    if (!this.collection)
      throw new ErrorAccessDenied('Database not configured')
    const doc = await this.collection.findOne(this.getFilter(data, {readOnly: true, ...options}))
    return doc ? this.validate(doc, {readOnly: true}) : undefined
  }

  async findMany (data, options) {
    if (!this.collection)
      throw new ErrorAccessDenied('Database not configured')
    const res = []
    await this.collection.find(this.getFilter(data || {}, options)).forEach(doc => res.push(this.validate(doc, {readOnly: true})))
    return res
  }

  async insert (data, options) {
    return this.update(data, {...options, insert: true})
  }

  async update (data, options) {
    if (!this.collection)
      throw new ErrorAccessDenied('Database not configured')
    if (options.validate !== false)
      data = this.validate(data, options)
    const unset = {}
    for (const n in data) {
      if (data[n] === undefined || data[n] === null) {
        data.$unset = unset
        unset[n] = 1
        delete data[n]
      }
    }
    await this.collection.findAndModify({query: this.getFilter(data, {required: true, validate: false, default: false}), update: data, upsert: options.insert})
  }

  async delete (data, options) {
    if (!this.collection)
      throw new ErrorAccessDenied('Database not configured')
    if (data._id)
      await this.collection.deleteOne(this.getFilter(data, options))
  }

  /**
   * Microserver middleware handler
   * @param {ServerRequest} req
   * @param {ServerResponse} res
   * @returns {Object}
   */
  handler (req, res) {
    res.isJson = true
    let filter = req.get.filter
    if (filter) {
      try {
        if (!filter.startsWith('{'))
          filter = Buffer.from(filter, 'base64').toString('utf-8')
        filter = JSON.parse(filter)
      } catch {
      }
    }
    switch (req.method) {
      case 'GET':
        if ('id' in req.params)
          return this.findOne({_id: req.params.id}, {user: req.user, params: req.params, filter}).then(res => ({data: res}))
        return this.findMany({}, {user: req.user, params: req.params, filter}).then(res => ({data: res}))
      case 'POST':
        return this.update(req.body, {user: req.user, params: req.params, insert: true, filter}).then(res => ({data: res}))
      case 'PUT':
        req.body._id = req.params.id
        return this.update(req.body, {user: req.user, params: req.params, insert: false, filter}).then(res => ({data: res}))
      case 'DELETE':
        return this.delete({_id: req.params.id}, {user: req.user, params: req.params, filter}).then(res => ({data: res}))
      default:
        return res.error(422)
    }
  }
}

/** minimalistic indexed mongo type collection with persistance for usage with Model */
export class MicroCollection {
  /**
   * @param {string} [options.name] - collection name
   * @param {FileStore} [options.store] - data store for data persistance
   * @param {function} [options.load] - data loader
   * @param {Object} [options.data] - fill with data
   */
  constructor(options = {}) {
    this.name = options.name || this.constructor.name
    const load = options.load ?? (options.store && (() => options.store.load(this.name, true)))
    if (load)
      this._ready = load(this).catch(() => {}).then(data => {
        this.data = data || {}
        this._ready = undefined
      })
    this.data = options.data || {}
  }

  query(query, data) {
    if (data)
      for (const n in query)
        if (data[n] !== query[n])
          return
    return data
  }

  async findOne(query) {
    await this._ready
    const id = query._id
    if (id)
      return this.query(query, this.data[id])
    let res
    await this.find(query).forEach(doc => (res = doc) && false)
    return res
  }

  find(query) {
    return {
      forEach: async (cb, self) => {
        await this._ready
        for (const id in this.data)
          if (this.query(query, this.data[id]))
            if (cb(this.data[id]) === false)
              break
      }
    }
  }

  async findAndModify(options) {
    if (!options.query)
      return
    const id = ((options.upsert || options.new) && !options.query._id) ? newObjectId() : options.query._id
    if (!id)
      return
    await this._ready
    const oldData = this.query(options.query, this.data[id])
    if (!oldData)
      this.data[id] = {_id: id, ...options.update}
    else
      Object.assign(oldData, options.update)
  }

  async deleteOne(query) {
    const id = query._id
    if (!id)
      return
    await this._ready
    delete this.data[id]
  }
}
