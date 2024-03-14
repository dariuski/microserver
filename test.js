import assert from 'assert'
import fs from 'fs/promises'
import { MicroServer, MicroCollection, Model, Controller, Auth, FileStore  } from './microserver.js'

global.test = (name, fn) => {(test.tests ||= []).push({ name, fn })}
test.skip = (name) => {if (!name) test._skip = true; else (test.tests ||= []).push({ name, skip: true })}
test.run = async () => {
  let prefix = test._prefix || ''
  test._count ||= 0
  test._failed ||= 0
  for (const obj of test.tests) {
    test._count++
    const stime = performance.now()
    try {
      test.tests = []
      test._prefix = prefix + '  '
      if (!(test._skip = obj.skip))
        await obj.fn()
      if (test._skip) {
        console.log(`${prefix}\x1b[90m- ${obj.name} (skipped)\x1b[0m`)
        test._count--
        continue
      }
      console.log(`${prefix}\x1b[32m✔️ ${obj.name}\x1b[90m (${(performance.now() - stime).toFixed(0)}ms)\x1b[0m`)
      if (test.tests.length) {
        await test.run()
      }
    } catch (e) {
      test._failed++
      console.log(`${prefix}\x1b[31m❌ ${obj.name}: ${e.message}\x1b[90m (${(performance.now() - stime).toFixed(0)}ms)\x1b[0m`)
      if (e.name !== 'AssertionError')
        console.error(e.stack)
    }
  }
  if (!prefix)
    console.log(`${test._failed?'\x1b[33m':'\x1b[32m'}${'_'.repeat(16)}\n${test._failed?'❌':'✔️'} ${test._count-test._failed}/${test._count} DONE\x1b[0m`)
}
process.nextTick(test.run)

function request(url, options) { return fetch('http://localhost:3100' + url, options).then(res => { const headers = {}; for (const [k, v] of res.headers) headers[k] = v; if (options?.response) { return { status: res.status, headers, text: () => res.text(), json: () => res.json() } } return headers['content-type'] === 'application/json' ? res.json() : res.text() } ) }
function GET(url, options) { return request(url, {...options, method: 'GET' }) }
function POST(url, data, options) { return request(url, {...options, method: 'POST', body: JSON.stringify(data) }) }
function PUT(url, data, options) { return request(url, {...options, method: 'PUT', body: JSON.stringify(data) }) }
function DELETE(url, options) { return request(url, {...options, method: 'DELETE' }) }

console.debug = () => {}

/** @type {MicroServer} */
let server

test('Prepare', async () => {
  await fs.mkdir('./tmp/public', { recursive: true })
})

test('Start server', async () => {
  server = new MicroServer({
    cors: '*',
    listen: 3100,
  })
  const events = {}
  server.on('listen', () => events.listen = true)
  await new Promise(resolve => server.on('ready', () => resolve()))
  assert(server._ready, 'Server not ready')
  assert(server.servers.size === 1, 'Server not ready')
  assert(events.listen, 'Event listen not fired')
})

test('CORS', async () => {
  test('OPTIONS', async () => {
    const res1 = await request('/', { method: 'OPTIONS', response: true} )
    assert.equal(res1.status, 204, 'Options not supported')
    assert.equal(res1.headers.allow, 'GET, HEAD, POST, PUT, PATCH, DELETE', 'Options not supported')
  })
  test('GET',  async() => {
    const res2 = await GET('/', { response: true, headers: { origin: 'http://localhost:3100' }} )
    assert.equal(res2.headers['access-control-allow-origin'], '*', 'CORS not supported')
    assert.equal(res2.headers['access-control-allow-credentials'], 'true', 'CORS not supported')
  })
})
  
test('Static', async () => {
  server.use('static', './tmp/public')
  await fs.writeFile('./tmp/public/index.html', '<html><body><h1>Hello World</h1></body></html>')
  await fs.writeFile('./tmp/public/index.dat', 'internal')
  await fs.writeFile('./tmp/index.txt', 'internal')
  test('GET', async() => assert.equal(await GET('/'), '<html><body><h1>Hello World</h1></body></html>', 'Invalid HTML content'))
  test('GET unknown', async() => assert.equal(await GET('/index.dat'), '404 Not found', 'Insecure file content'))
  test('GET invalid', async() => assert.equal(await GET('/../index.txt'), '404 Not found', 'Insecure file content'))
  test('GET 304', async() => {
    const headers = (await GET('/index.html', { response: true })).headers
    const res = await GET('/index.html', { response: true, headers: {'if-none-match': headers.etag, 'if-modified-since': headers['last-modified']} })
    assert.equal(res.status, 304)
  })
  test('HEAD', async() => {
    const res = await request('/index.html', { method: 'HEAD', response: true })
    assert.equal(res.status, 200)
    assert(res.headers['content-length'] > 0)
    assert.equal(await res.text(), '')
  })
})

test('Routes: stack', async () => {
  assert.equal(server.router._stack.length, 0, 'Invalid stack')
  server.use((req, res, next) => {
    if (req.get.test)
      return {test: req.get.test, body: req.body}
    next()
  })
  assert.deepEqual(await GET('/test1?test=test-a'), {success: true, test: 'test-a', body: {}})
  assert.deepEqual(await POST('/test2?test=test-b', {test2: 'test-b'}), {"success":true,"test":"test-b","body":{"test2":"test-b"}})
  assert.equal(await GET('/test2'), '404 Not found')
})

test('Routes: GET', async () => {
  server.router.clear()
  assert.equal(server.router._tree.GET, undefined, 'Invalid routes')
  server.use('GET', '/test1', (req, res) => {
    if (req.get.a)
      return res.jsonSuccess({ a: req.get.a })
    if (req.get.b)
      return { b: req.get.b }
    if (req.get.c)
      return Promise.resolve({ c: req.get.c })
    return ''
  })
  assert.equal(server.router._stack.length, 0, 'Invalid route /test1')
  assert.equal(server.router._tree.GET?.tree?.test1?.next?.length, 1, 'Invalid route /test1')
  assert.deepEqual(await GET('/test1?a=test-a'), {success: true, a: 'test-a'})
  assert.deepEqual(await GET('/test1?b=test-b'), {success: true, b: 'test-b'})
  assert.deepEqual(await GET('/test1?c=test-c'), {success: true, c: 'test-c'})
  assert.equal(await GET('/test1'), '')
})

test('Routes: POST', async () => {
  server.router.clear()
  assert.equal(server.router._tree.POST, undefined, 'Invalid routes')
  server.use('POST', '/test2/:id', (req, res) => {
    return {data: req.body, id: req.params.id}
  })
  server.use('POST', '/test3/:id2*', (req, res) => {
    throw new Error('Access denied')
  })
  assert.equal(server.router._stack.length, 0, 'Invalid route /test2')
  assert.equal(server.router._tree.POST?.tree?.test2?.param?.next?.length, 1, 'Invalid route /test2/:id')
  assert.equal(server.router._tree.POST?.tree?.test3?.last?.next?.length, 1, 'Invalid route /test2/:id2*')
  assert.deepEqual(await POST('/test2', {a: 'test2-a'}), {success:false, error: 'Not found'})
  assert.deepEqual(await POST('/test2/prm', {b: 'test2-b'}), {success: true, data: {b: 'test2-b'}, id: 'prm'})
  assert.deepEqual(await POST('/test3/prm/error', {b: 'test2-b'}), {success: false, error: 'Access denied'})
  assert.equal(await GET('/test2'), '404 Not found')
})

test('Routes: path', async () => {
  server.router.clear()
  assert.equal(server.router._tree.GET, undefined, 'Invalid routes')
  server.use('GET', '/test2/:id', () => {})
  assert(server.router._tree.GET?.tree?.test2?.param, 'invalid route /test2/:id')
  server.use('GET /test3/:id', () => {})
  assert(server.router._tree.GET?.tree?.test3?.param, 'invalid route /test3/:id')
  server.use({'GET /test4/p1': () => {}, 'GET /test4/p2': () => {}})
  assert(server.router._tree.GET?.tree?.test4?.tree?.p1, 'invalid route /test4/p1')
  assert(server.router._tree.GET?.tree?.test4?.tree?.p2, 'invalid route /test4/p2')
  server.use('/test5', {'GET /p1': () => {}, 'GET /p2': () => {}})
  assert(server.router._tree.GET?.tree?.test5?.tree?.p1, 'invalid route /test5/p1')
  assert(server.router._tree.GET?.tree?.test5?.tree?.p2, 'invalid route /test5/p2')
  server.use('/test6', [ ['GET /p1', () => {}], ['GET', '/p2', () => {}]])
  assert(server.router._tree.GET?.tree?.test6?.tree?.p1, 'invalid route /test5/p1')
  assert(server.router._tree.GET?.tree?.test6?.tree?.p2, 'invalid route /test5/p2')
})

test('Controller', async () => {
  class TestController extends Controller {
    async insert(id) {
      return {data: {id}}
    }

    async update(company, id) {
      return {data: {company, id}}
    }

    async get(company, id) {
      return {data: {company, id}}
    }

    async all(company) {
      return {data: {company}}
    }

    async update$admin$user(id) {
      return {data: {id}}
    }

    static 'acl:POST /login' = ''
    async 'POST /login'() {
      return {data: this.req.body}
    }

    static 'user:login2' = 'test'
    static 'url:login2' = 'POST /login2'
    async login2() {
      return {data: this.req.body}
    }

    static 'role:login3' = 'test2'
    static 'url:login3' = 'POST /login3'
    async login3() {
      return {data: this.req.body}
    }
  }
  const routes = TestController.routes()
  assert(routes.find(o => o[0] === 'POST /login' && typeof o[1] === 'function'), 'POST /login')
  assert(routes.find(o => o[0] === 'POST /login2' && o[1] === 'user:test'), 'POST /login2')
  assert(routes.find(o => o[0] === 'POST /login3' && o[1] === 'role:test2'), 'POST /login3')
  assert(routes.find(o => o[0] === 'POST /:id' && o[1] === 'acl:insert'), 'insert')
  assert(routes.find(o => o[0] === 'PUT /admin/user/:id' && o[1] === 'acl:update'), 'update/admin/user')
  assert(routes.find(o => o[0] === 'PUT /:p0/:p1' && o[1] === 'acl:update'), 'update')
  assert(routes.find(o => o[0] === 'GET /:p0/:p1' && o[1] === 'acl:get'), 'get')
  assert(routes.find(o => o[0] === 'GET /:id' && o[1] === 'acl:all'), 'all')
  server.use('/api', TestController)
  server.use((req, res, next) => {
    req.user = {id: 'test', acl: {get: true, insert: false, update: true, all: false}}
    req.auth = new Auth(req, res, req.server.auth.options)
    next()
  })
  test('Login', async () => assert.deepEqual(await POST('/api/login', {user: 'test'}), {success: true, data: {user: 'test'}}))
  test('Login2', async () => assert.deepEqual(await POST('/api/login2', {user: 'test2'}), {success: true, data: {user: 'test2'}}))
  test('Login3', async () => assert.deepEqual(await POST('/api/login3', {user: 'test3'}), {success: false, error: 'Access denied'}))
  test('Prm1', async () => assert.deepEqual(await POST('/api/prm1', {}), {success: false, error: 'Access denied'}))
  test('Prm2', async () => assert.deepEqual(await PUT('/api/prm1/prm2', {}), {success: true, data: {company: 'prm1', id: 'prm2'}}))
})

test('Model', async () => {
  const subModel = new Model({name: String})
  const model = new Model({
    _id: 'ObjectId',
    name: String,
    field1: {type: 'String', format: 'email'},
    field2: {type: 'String', required: true},
    field3: {type: 'Number', canRead: false},
    field4: {type: 'String', default: 'test'},
    field5: {type: 'String', canWrite: false, default: '${user.name}'},
    field6: {type: Date, canWrite: false, default: () => new Date('2020-01-01'), required: true},
    field7: {type: 'any', default: (options) => options.field.type},
    field8: {type: 'any', canWrite:'${user.acl.insert}', canRead:'${user.acl.get}'},
    field9: {type: 'any', canWrite:'${user.acl.update}'},
    field10: {type: subModel},
    field11: {type: Array},
    field12: {type: [String], enum: ['123', '456'] },
    field13: {type: [subModel]}
  }, {name: 'test'})
  assert(model.name === 'test', 'Model name')
  assert(model.model._id.type === 'ObjectId', 'Model _id')
  assert(model.model.name.type === 'string', 'Model name')
  assert(model.model.field1.type === 'string', 'Model field1')
  assert(model.model.field2.type === 'string', 'Model field2')
  assert(model.model.field3.type === 'number', 'Model field3')
  assert(model.model.field4.type === 'string', 'Model field4')
  assert(model.model.field5.type === 'string', 'Model field5')
  assert(model.model.field6.type === 'date', 'Model field6')
  assert(model.model.field7.type === 'any', 'Model field7')
  assert(model.model.field8.type === 'any', 'Model field8')
  assert(model.model.field9.type === 'any', 'Model field9')
  assert(model.model.field9.type === 'any', 'Model field9')
  test('doc1', () => assert.deepEqual(model.validate({ name: 'test', field1: 'test@example.com', field2: 'test', field3: 123, field4: 'test', field5: 'test', field6: 'test', field8: 'test', field9: 'test' }, {insert: true, user: {name:'test', acl: {insert: true}}}),{name: 'test', field1: 'test@example.com', field2: 'test', field3: 123, field4: 'test', field5: 'test', field6: new Date('2020-01-01'), field7: 'any', field8: 'test'}))
  test('doc2', () => assert.deepEqual(model.validate({ name: 'test', field1: 'test', field2: 'test', field3: 123, field4: 'test', field5: 'test', field6: 'test', field8: 'test', field9: 'test' }, {readOnly: true, user: {name:'test', acl: {insert: true}}}),{name: 'test', field1: 'test', field2: 'test', field4: 'test', field5: 'test', field6: 'test', field9: 'test'}))
  test('submodel', () => assert.deepEqual(model.validate({ field2: 'test', field4: null, field10: {name: 'test', value: 'test'} }, {}),{field2: 'test', field4: null, field6: new Date('2020-01-01'), field7: 'any', field10: {name: 'test'}}))
  test('array', () => assert.deepEqual(model.validate({ field2: 'test', field11: [] }, {default: false}),{field2: 'test', field11: []}))
  test('string array', () => assert.deepEqual(model.validate({ field2: 'test', field12: ['123', 456] }, {default: false}),{field2: 'test', field12: ['123', '456']}))
  test('submodel array', () => assert.deepEqual(model.validate({ field2: 'test', field13: [{name: 'test1'}, {value: 'test2'}] }, {default: false}),{field2: 'test', field13: [{name: 'test1'}, {}]}))
})

test('Model invalid', async () => {
  const model = new Model({
    _id: 'ObjectId',
    field1: {type: 'Number', required: true, validate: v => v > 0 && v < 10},
    field2: {type: 'String', format: 'email'},
    field3: {type: Date, canRead: false},
    field4: {type: [String], enum: ['red', 'green']},
    field5: {type: 'int', minimum: 1, maximum: 10},
  }, {name: 'test'})

  async function asserError(fn, check) {
    try {
      await fn()
    } catch (e) {
      return assert(e.message.includes(check), e.message)
    }
    assert.fail('Does not throw error')
  }
  test('Null', () => asserError(() => model.validate({field1: null}), 'Invalid field: field1'))
  test('Required', () => asserError(() => model.validate({}), 'Invalid field: field1'))
  test('Number 0', () => asserError(() => model.validate({field1: 0}), 'Invalid field: field1'))
  test('Number text', () => asserError(() => model.validate({field1: 'test'}), 'Invalid field: field1'))
  test('Email empty', () => asserError(() => model.validate({field1: 1, field2: ''}), 'Invalid field: field2'))
  test('Email format', () => asserError(() => model.validate({field1: 1, field2: 'a@#b'}), 'Invalid field: field2'))
  test('Date format', () => asserError(() => model.validate({field1: 1, field3: '14.15-16'}), 'Invalid field: field3'))
  test('Enum', () => asserError(() => model.validate({field1: 1, field4: ['blue']}), 'Invalid field: field4'))
  test('Min', () => asserError(() => model.validate({field1: 1, field5: 0}), 'Invalid field: field5'))
  test('Max', () => asserError(() => model.validate({field1: 1, field5: 11}), 'Invalid field: field5'))
})

test('Model store', async () => {
  server.router.clear()
  const model = new Model({_id: 'ObjectId', name: String}, {name: 'test', collection: new MicroCollection()})
  server.get('/test', model)
  server.get('/test/:id', model)
  server.post('/test', model)
  server.put('/test/:id', model)
  server.delete('/test/:id', model)
  test('insert', async () => {
    await POST('/test', {name: 'test'})
    const doc = Object.values(model.collection.data)[0]
    assert(doc, 'Document not created')
    assert.equal(doc.name, 'test')
  })
  test('get', async () => {
    const _id = (await model.findOne({}))?._id
    assert.deepEqual(await GET('/test'), {success: true, data: [{_id, name: 'test'}]})
    assert.deepEqual(await GET('/test/' + _id), {success: true, data: {_id, name: 'test'}})
  })
  test('update', async () => {
    const _id = (await model.findOne({}))?._id
    assert(_id, 'Does not exist')
    await PUT('/test/' + _id, {name: 'test2'})
    assert.deepEqual(await GET('/test/' + _id), {success: true, data: {_id, name: 'test2'}})
  })
  test('delete', async () => {
    const _id = (await model.findOne({}))?._id
    assert(_id, 'Does not exist')
    await DELETE('/test/' + _id)
    assert.deepEqual(await GET('/test'), {success: true, data: []})
  })
})

test('FileStore', async () => {
  const store = new FileStore({dir: './tmp', debounceTimeout: 200})
  await fs.writeFile('./tmp/test', JSON.stringify({name: 'test'}))
  const data = await store.load('test', true)
  test('data', () => assert.deepEqual(data, {name: 'test'}))
  test('change', async () => {
    data.name = 'test2'
    assert.equal(await fs.readFile('./tmp/test', 'utf8'), JSON.stringify({name: 'test'}))
  })
  test('ready', async () => {
    data.name = 'test3'
    await store.ready()
    assert.equal(await fs.readFile('./tmp/test', 'utf8'), JSON.stringify({name: 'test3'}))
  })
})

test('Stop server', async () => {
  await server.close()
  assert(server.servers.size === 0, 'Server not closed')

  await new Promise(resolve => setTimeout(resolve, 10)) // closing listening port needs some time
})

test('Auth', async () => {
  const usersCollection = new MicroCollection({ store: new FileStore({ dir: 'tmp' }), name: 'users' })

  const userProfile = new Model({
    _id: 'string',
    name: { type: 'string', required: true },
    email: { type: 'string', format: 'email' },
    password: { type: 'string', canRead: false },
    role: { type: 'string' },
    acl: { type: 'object' },
  }, { collection: usersCollection, name: 'user' })

  const server = new MicroServer({
    listen: 3100,
    auth: {
      token: 'test',
      users: (user, password) => userProfile.findOne({_id: user, password })
    }
  })

  await userProfile.insert({_id: 'admin', name: 'admin', password: 'secret', role: 'admin', acl: {'user/*': true}})

  server.use('POST /login', async (req) => {
    const user = await req.auth.login(req.body.user, req.body.password)
    return user ? { user } : 403
  })
  server.use('GET /profile', 'acl:auth', req => ({ user: req.user }))
  server.use('GET /admin/users', 'role:admin', userProfile)
  server.use('GET /admin/user/:id', 'acl:user/get', userProfile)
  server.use('POST /admin/user', 'role:admin', 'acl:user/insert', userProfile)
  server.use('PUT /admin/user/:id', 'acl:user/update', userProfile)
  server.use('DELETE /admin/user/:id', 'acl:user/delete', userProfile)
  await new Promise(resolve => server.on('ready', () => resolve()))

  let options

  test('Login', async () => {
    const res = await POST('/login', { user: 'admin', password: 'secret' }, { response: true })
    assert.equal(res.status, 200)
    assert.match(res.headers['set-cookie'] || '', /token=\w+/)
    options = {headers: { cookie: res.headers['set-cookie'].match(/token=[^;]+/)[0] }}
  })

  test('Profile', async () => assert.equal((await GET('/profile', options))?.user?._id, 'admin'))
  test('Update', async () => {
    assert.deepEqual((await PUT('/admin/user/admin', {name: 'Test'}, options)), {success: true})
    assert.equal((await userProfile.findOne({_id: 'admin'})).name, 'Test')
  })
  test('Cleanup', () => server.close())
})

test('Cleanup', async () => {
  await fs.rm('./tmp', { recursive: true })
})
