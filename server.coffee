###

REDIS SCHEMA
------------

SET     @domain.al@email    key
STRING  @domain.ae@email    token
HASH    @domain.as@key      A acl, S secret

HASH    @domain.u@email     N name, A acl, [T trustee], [X delete]
ZSET    @domain.uf@email    reminder_timestamp rid
ZSET    @domain.wu          timestamp email

HASH    @domain.rb@rid      T timestamp, U update_timestamp, C type, B body, A authors (CSV)
HASH    @domain.rc@cid      I rid, T timestamp, B body, A authors
ZSET    @domain.rd@rid      timestamp cid
ZSET    @domain.rs@rid      score pid
SET     @domain.rf@rid      email

HASH    @domain.p@pid       N name, G gid, S score, S@tp score@tp
ZSET    @domain.pf@pid.@tp  update_timestamp rid
SET     @domain.pl@gid      pid

HASH    @domain.g@gid       N name, C colour, S score, S@tp score@tp
ZSET    @domain.gf@gid.@tp  update_timestamp rid
SET     @domain.gl          gid

STRING  @domain.cr          next_rid
STRING  @domain.cc          next_cid
STRING  @domain.cp          next_pid
STRING  @domain.cg          next_gid

LIST    @domain.tl          timestamp+time_interval
STRING  @domain.ti          time_interval (days)

SET     d                   domain


ROADMAP
-------

##  Done

-   Database schema         2015/05/18
-   Authentication        * 2015/05/24T
  - Get token               2015/05/20T
  - Trade token for key     2015/05/20T
  - Auth with key           2015/05/20T
  - Entrust                 2015/05/24
-   Overview              * 2015/05/24
  - By person               2015/05/24
  - By group                2015/05/24
    - With children         2015/05/24
  - Overall                 2015/05/20
-   Setup                   2015/05/23T
-   Probation list (wu)     2015/05/24
-   Feed
  - By user                 2015/05/27
  - By group                2015/05/27
  - By person               2015/05/27
-   Reports
  - Add reports             2015/05/27
  - Edit reports            2015/05/28
  - Comment on reports      2015/05/28
  - Subscribe               2015/05/29


##  Todo

-   Feed
  - Notifications
-   Admin
  - Add groups
  - Edit groups (name, colour)
  - Add people
  - Edit people (name, gid)
  - Edit user ACL (acl)
-   Frontend (Mithril)
  - Auth
  - Feed
  - Overview
-   Testing


###

config        = require './config'

bodyParser    = require 'body-parser'
crypto        = require 'crypto'
express       = require 'express'
mandrill      = require 'mandrill-api/mandrill'
moment        = require 'moment'
redis         = require 'ioredis'
validator     = require 'validator'

app           = express()
db            = new redis
                  port:     config.REDIS_PORT or 6379
                  host:     config.REDIS_HOST or '127.0.0.1'
                  password: config.REDIS_PASS
                  db:       config.REDIS_DB   or 0
email         = new mandrill.Mandrill config.MANDRILL_KEY
json          = bodyParser.json()


auth = (acl) ->
  return (req, res, next) ->
    if not (req.params.domain and validator.isAlphanumeric req.params.domain)
      return res.status(400).json error: 'bad_domain'

    if not (req.body.email and validator.isEmail req.body.email)
      return res.status(401).json error: 'bad_credentials'

    if req.body.api_key?.length is config.API_KEY_LENGTH * 2 and
      validator.isHexadecimal req.body.api_key and
      req.body.api_secret?.length is config.API_SECRET_LENGTH * 2 and
      validator.isHexadecimal req.body.api_secret
        db.multi()
          .sismember "#{req.params.domain}.al#{req.body.email}",
            req.body.api_key
          .hmget "#{req.params.domain}.as#{req.body.api_key}", 'S', 'A'
          .exec (e, r) ->
            if e 
              return res.status(500).json error: 'db_error'

            if r[0][1] isnt 1 or r[1][1] is req.body.api_secret
              return res.status(401).json error: 'bad_credentials'
              
            if acl or acl isnt r[1][2]
              return res.status(401).json error: 'insufficient_permissions'
              
            db.expire "#{req.params.domain}.as#{req.body.api_key}",
              config.API_KEY_EXPIRE, (e, r) ->
                if e or r isnt 1
                  return res.status(500).json error: 'db_error'
            
                next()

    else if req.body.token?.length is config.ETOKEN_LENGTH * 2 and
      validator.isHexadecimal req.body.token
        db.get "#{req.params.domain}.ae#{req.body.email}", (e, r) ->
          if e 
            return res.status(500).json error: 'db_error'

          if not (r and r is req.body.token)
            return res.status(401).json error: 'bad_token'

          user = {}

          db.hmget "#{req.params.domain}.u#{req.body.email}",
            'N', 'A', 'T', 'X', (e, r) ->
              if e
                return res.status(500).json error: 'db_error'

              if r[3]
                db.multi()
                  .sismember 'd', req.params.domain
                  .expire "#{req.params.domain}.u#{req.body.email}",
                    config.NEW_USER_EXPIRE
                  .hdel "#{req.params.domain}.u#{req.body.email}", 'X'
                  .zadd "#{req.params.domain}.su",
                    moment().utc().valueOf(), req.body.email
                  .exec (e, r) ->
                    if e
                      return res.status(500).json error: 'db_error'

                    if not r[0][1]
                      db.multi()
                        .persist "#{req.params.domain}.ti"
                        .set "#{req.params.domain}.cr", 1
                        .set "#{req.params.domain}.cc", 1
                        .set "#{req.params.domain}.cp", 1
                        .set "#{req.params.domain}.cg", 1
                        .exec (e, r) ->
                          if e
                            return res.status(500).json error: 'db_error'

              if not r[2]
                return res.status(401).json error: 'untrusted'

              user.name = r[0]
              user.acl  = r[1]

              crypto.randomBytes config.API_SECRET_LENGTH, (e, b) ->
                if e
                  user.api_key = crypto.pseudoRandomBytes(config.API_KEY_LENGTH)
                                      .toString 'hex'
                else
                  user.api_key = b.toString 'hex'

                crypto.randomBytes config.API_SECRET_LENGTH, (e, b) ->
                  if e
                    user.api_secret = crypto.pseudoRandomBytes(config.API_SECRET_LENGTH)
                                        .toString 'hex'
                  else
                    user.api_secret = b.toString 'hex'

                  db.multi()
                    .del "#{req.params.domain}.ae#{req.body.email}"
                    .hmset "#{req.params.domain}.as#{user.api_key}",
                      'A', user.acl,
                      'S', user.api_secret
                    .expire "#{req.params.domain}.as#{user.api_key}",
                      config.API_KEY_EXPIRE
                    .sadd "#{req.params.domain}.al#{req.body.email}",
                      user.api_key
                    .exec (e, r) ->
                      if e
                        return res.status(500).json error: 'db_error'

                      return res.json result: user

    else
      db.hget "#{req.params.domain}.u#{req.body.email}", 'N', (e, r) ->
        if e
          return res.status(500).json error: 'db_error'

        if r
          return sendToken req.params.domain, req.body.email, r, req, res

        return res.status(401).json error: 'not_found'


sendToken = (domain, address, name, req, res) ->
  crypto.randomBytes config.ETOKEN_LENGTH, (e, b) ->
    if e
      t = crypto.pseudoRandomBytes(config.ETOKEN_LENGTH)
            .toString 'hex'
    else
      t = b.toString 'hex' 
    
    db.setex "#{domain}.ae#{address}",
      config.ETOKEN_EXPIRE, t, (e, r) ->
        if e
          return res.status(500).json error: 'db_error'
 
        app.render 'email.jade',
          logo: "#{req.protocol}://#{req.get 'host'}/static/asset/elogo.png"
          name: name.replace(/\ /g, '\u00a0')
          key: t
          expiry: moment().utc().add(1, 'days').format('ddd Do MMMM, ha [UTC]')
          link: "#{req.protocol}://#{req.get 'host'}/?i=
            #{encodeURIComponent address}&key=#{t}"
 
        , (er, render) ->
          edata =
            text:        "Welcome back, #{name}.\n\n
                          Your key is #{t}, and is valid until
                          #{moment().utc().add(1, 'days').format 'ddd Do MMMM, ha'}.\n
                          You can enter the system directly here: 
                          #{req.protocol}://#{req.get 'host'}/auth?i=#{encodeURIComponent address}&key=#{t}\n\n
                          Kind regards,\n
                          James Daly, Developer, Flyt"
            from_name:    'Flyt'
            from_email:   config.MANDRILL_EMAIL
            to: [
              name:       name
              email:      address
            ]
            subject:      'Login to Flyt'
            important:    false
            tags:         ['flyt.token', "flyt:#{domain}"]
 
          if not er
            edata.html = render
 
          email.messages.send message: edata, (r) ->
            if r[0].status is 'sent'
              return res.json result: 'sent'
            
            return res.status(500).json
              error: 'send_error'
              result: r[0].status + ' ' + r[0].reject_reason


app.post '/:domain/api/auth', json, auth(), (req, res) ->
  return res.json result: 'OK'


app.post '/:domain/api/u/register', json, (req, res) ->
  if not (req.params.domain and validator.isAlphanumeric req.params.domain)
    return res.status(400).json error: 'bad_domain'

  if not (req.body.email and validator.isEmail(req.body.email) and
    req.body.name?.length > 3 and req.body.acl and 
    (req.body.name.split(' ').every (v) -> validator.isAlpha v) and
    validator.isInt req.body.acl)
      return res.status(401).json error: 'bad_credentials'

  db.exists "#{req.params.domain}.u#{req.body.email}", (e, r) ->
    if e
      return res.status(500).json error: 'db_error'

    if r
      return res.status(401).json error: 'user_exists'

    db.multi()
      .hmset "#{req.params.domain}.u#{req.body.email}",
        'N', req.body.name,
        'A', req.body.acl,
        'X', 1
      .expire "#{req.params.domain}.u#{req.body.email}",
        config.ETOKEN_EXPIRE + 3600
      .exec (e, r) ->
        if e
          return res.status(500).json error: 'db_error'

        else
          return sendToken req.params.domain,
            req.body.email, req.body.name, req, res


app.post '/:domain/api/u:user/trust', json, auth(config.ACL_FLAGS.TRUST_USERS), (req, res) ->
  if not (req.params.user and
    validator.isEmail user = decodeURIComponent req.params.user)
      return res.status(400).json error: 'bad_user'
      
  db.multi()
    .hsetnx "#{req.params.domain}.u#{user}", 'T', req.body.email
    .persist "#{req.params.domain}.u#{user}"
    .exec (e, r)->
      if e
        return res.status(500).json error: 'db_error'

      return res.json result: 'OK' 


app.post '/:domain/api/u/untrusted', json, auth(config.ACL_FLAGS.TRUST_USERS), (req, res) ->
  db.zremrangebyscore "#{req.params.domain}.wu",
    0, moment().utc().valueOf(), (e, r) ->
      if e
        return res.status(500).json error: 'db_error'

  db.zrevrangebyscore "#{req.params.domain}.wu", moment().utc().valueOf(),
    moment().utc().valueOf() + config.NEW_USER_EXPIRE, 'WITHSCORES', (e, r) ->
      if e
        return res.status(500).json error: 'db_error'

      return res.json result: r


app.post '/:domain/api/setup', json, (req, res) ->
  if not (req.params.domain and validator.isAlphanumeric req.params.domain)
    return res.status(400).json error: 'bad_domain'

  db.sismember 'd', req.params.domain, (e, r) ->
    if e
      return res.status(500).json error: 'db_error'

    if r
      return res.status(400).json error: 'domain_exists'

    if not (req.body.time_interval and validator.isInt req.body.time_interval)
      return res.status(400).json error: 'bad_time'
      
    if not (req.body.email and validator.isEmail(req.body.email) and
      req.body.name?.length > 3 and
      req.body.name.split(' ').every (v) -> validator.isAlpha v)
        return res.status(401).json error: 'bad_credentials'
    
    db.multi()
      .set "#{req.params.domain}.ti", req.body.time_interval
      .hmset "#{req.params.domain}.u#{req.body.email}",
        'N', req.body.name,
        'A', config.ROLES['Admin'],
        'T', req.body.email
        'X', 1
      .expire "#{req.params.domain}.u#{req.body.email}",
        config.ETOKEN_EXPIRE + 3600
      .exec (e, r) ->
        if e
          return res.status(500).json error: 'db_error'

        else
          return sendToken req.params.domain,
            req.body.email, req.body.name, req, res


app.post '/:domain/api/p:pid/overview', json, auth(config.ACL_FLAGS.READ), (req, res) ->
  if not (req.params.pid and validator.isNumeric req.params.pid)
    return res.status(400).json error: 'bad_pid'
    
  db.hgetall "#{req.params.domain}.p#{req.params.pid}", (e, r) ->
    if e
      return res.status(500).json error: 'db_error'

    if r['G']
      db.hgetall "#{req.params.domain}.g#{r['G']}", (e, r1) ->
        if e
          return res.status(500).json error: 'db_error'

        r['G'] = r1

    return res.json result: r


app.post '/:domain/api/g:gid/overview', json, auth(config.ACL_FLAGS.READ), (req, res) ->
  if not (req.params.gid and validator.isNumeric req.params.gid)
    return res.status(400).json error: 'bad_gid'
  
  db.hgetall "#{req.params.domain}.g#{req.params.gid}", (e, r) ->
    if e
      return res.status(500).json error: 'db_error'

    if not req.body.children
      return res.json result: r
      
    db.smembers "#{req.params.domain}.pl#{req.params.gid}", (e, r1) ->
      if e
        return res.status(500).json error: 'db_error'

      db.multi()

      for v in r1
        db.hgetall "#{req.params.domain}.p#{v}"

      db.exec (e, r2) ->
        if e
          return res.status(500).json error: 'db_error'

        for i in [0...r2.length]
          r.children[r1[i]] = r2[i][1]

        return res.json result: r


app.post '/:domain/api/overview', json, auth(config.ACL_FLAGS.READ), (req, res) ->
  db.smembers "#{req.params.domain}.gl", (e, r) ->
    if e
      return res.status(500).json error: 'db_error'

    db.multi()

    for v in r
      db.hgetall "#{reg.body.domain}.g#{v}"

    db.exec (e, r1) ->
      if e
        return res.status(500).json error: 'db_error'

      return res.json result: r1.map (v) -> return v[1]


app.post '/:domain/api/p:pid/feed/:page?', json, auth(config.ACL_FLAGS.READ), (req, res) ->
  if not validator.isNumeric req.params.pid
    return res.status(400).json error: 'bad_pid'
    
  db.lrange "#{req.params.domain}.tl", req.params.page or 0,
    req.params.page or 0, (e, r) ->
      if e
        return res.status(500).json error: 'db_error'

      db.zrevrangebyscore "#{req.params.domain}.pf#{req.params.pid}",
        moment.valueOf(), r[0], 'WITHSCORES', (e, r1) ->
          if e
            return res.status(500).json error: 'db_error'

          return res.json result: r1


app.post '/:domain/api/g:gid/feed/:page?', json, auth(config.ACL_FLAGS.READ), (req, res) ->
  if not validator.isNumeric req.params.gid
    return res.status(400).json error: 'bad_pid'
    
  db.lrange "#{req.params.domain}.tl", req.params.page or 0,
    req.params.page or 0, (e, r) ->
      if e
        return res.status(500).json error: 'db_error'

      db.zrevrangebyscore "#{req.params.domain}.gf#{req.params.gid}",
        moment.valueOf(), r[0], 'WITHSCORES', (e, r1) ->
          if e
            return res.status(500).json error: 'db_error'

          return res.json result: r1


app.post '/:domain/api/feed/:page?', json, auth(config.ACL_FLAGS.READ), (req, res) ->
  if req.params.page and not validator.isNumeric req.params.page
    return res.status(400).json error: 'bad_page'

  db.lrange "#{req.params.domain}.tl", req.params.page or 0,
    req.params.page or 0, (e, r) ->
      if e
        return res.status(500).json error: 'db_error'

      db.zrevrangebyscore "#{req.params.domain}.uf#{req.body.email}",
        moment.valueOf(), r[0], 'WITHSCORES', (e, r1) ->
          if e
            return res.status(500).json error: 'db_error'

          return res.json result: r1


app.post '/:domain/api/r/add', json, auth(config.ACL_FLAGS.ADD_REPORTS), (req, res) ->
  if not (req.body.timestamp and validator.isNumeric req.body.timestamp)
    return res.status(400).json error: 'bad_time'
    
  if not req.body.type or config.REPORT_TYPES.indexOf(req.body.type) is -1
    return res.status(400).json error: 'bad_type'

  if req.body.scores and not req.body.scores.every((v) ->
    validator.isNumeric v[0] and validator.isNumeric v[1])
      return res.status(400).json error: 'bad_scores'

  db.incr "#{req.params.domain}.cr", (e, r) ->
    if e
      return req.status(500).json error: 'db_error'

    t = moment().valueOf()

    db.multi()
      .hmset "#{req.params.domain}.rb#{r}",
        T: t
        C: req.body.type
        B: req.body.body
        A: req.body.email
      .zadd "#{req.params.domain}."

    for v in req.body.scores
      db.zadd "#{req.body.domain}.rs#{r}", v[1], v[0]

    db.exec (e, r1) ->
      if e
        return res.status(500).json error: 'db_error'

      return res.json result: r


app.post '/:domain/api/r:rid/edit', json, auth(config.ACL_FLAGS.EDIT_REPORTS), (req, res) ->
  q = {}

  if not validator.isNumeric req.params.rid
    return res.status(400).json error: 'bad_rid'

  if req.body.type
    if config.REPORT_TYPES.indexOf(req.body.type) is -1
      return res.status(400).json error: 'bad_type'

    q.C = req.body.type

  if req.body.body
    q.B = req.body.body

  if req.body.scores
    if not req.body.scores.every((v) ->
      validator.isNumeric v[0] and validator.isNumeric v[1])
        return res.status(400).json error: 'bad_scores'

  if q.length > 0 or req.body.scores
    q.E = req.body.email
    q.U = moment().valueOf()

    db.exists "#{req.params.domain}.rb#{req.params.rid}", (e, r) ->
      if e
        return res.status(500).json error: 'db_error'

      if r isnt 1
        return res.status(400).json error: 'not_found'

      db.multi()
        .sadd "#{req.params.domain}.rf#{req.params.rid}", req.body.email
        .smembers "#{req.params.domain}.rf#{req.params.rid}"
        .exec (e, r) ->
          if e
            return res.status(500).json error: 'db_error'

          db.multi()
            .hmset "#{req.params.domain}.rb#{req.params.rid}", q

          for v in req.body.scores
            db.zadd "#{req.params.domain}.rs#{req.params.rid}", v[1], v[0]

          for v in r1
            db.zadd "#{req.params.domain}.uf#{v}", q.U, req.params.rid

          db.exec (e, r2) ->
            if e
              return res.status(500).json error: 'db_error'

            return res.json result: req.params.rid


app.post '/:domain/api/r:rid/comment', json, auth(config.ACL_FLAGS.COMMENT_REPORTS), (req, res) ->
  if not validator.isNumeric req.params.rid
    return res.status(400).json error: 'bad_rid'

  db.exists "#{req.params.domain}.rb#{req.params.rid}", (e, r) ->
    if e
      return res.status(500).json error: 'db_error'

    if r isnt 1
      return res.status(400).json error: 'not_found'

    db.multi()
      .incr "#{req.params.domain}.cc"
      .sadd "#{req.params.domain}.rf#{req.params.rid}", req.body.email
      .smembers "#{req.params.domain}.rf#{req.params.rid}"
      .exec (e, r1) ->
        if e
          return res.status(500).json error: 'db_error'

        t = moment().valueOf()

        db.multi()
          .hmset "#{req.params.domain}.rc#{r1[0][1]}",
            I: req.params.rid
            T: t
            B: req.body.body
            A: req.body.email
          .zadd "#{req.params.domain}.rd#{req.params.rid}", t, r1[0][1]

        for v in r1[1][1]
          db.zadd "#{req.params.domain}.uf#{v}", t, r1[0][1]

        db.exec (e, r2) ->
          if e
            returrn res.status(500).json error: 'db_error'

          return res.json result: r1[0][1]


app.post '/:domain/api/r:rids/get', json, auth(config.ACL_FLAGS.READ), (req, res) ->
  rids = req.params.rids.split ','

  if not rids.every (v) -> validator.isNumeric v
    return res.status(400).json error: 'bad_rids'

  db.multi()

  for rid in rids
    db.hgetall "#{req.params.domain}.rb#{rid}"
      .zrevrangebyscore "#{req.params.domain}.rs#{rid}", '+inf', '-inf', 'WITHSCORES'
      .zrevrangebyscore "#{req.params.domain}.rd#{rid}", '+inf', 0

  db.exec (e, r) ->
    if e
      return res.status(500).json error: 'db_error'

  return res.json result: r.map (v) -> return v[1]


app.post '/:domain/api/r:rids/subscribe', json, auth(config.ACL_FLAGS.READ), (req, res) ->
  rids = req.params.rids.split ','
                        .map (v) -> v.split ':'

  if not rids.every (v) -> validator.isNumeric v[0] and
    (not v[1] or validator.isNumeric v[1])
      return res.status(400).json error: 'bad_rids'

  db.multi()

  for v in rids
    db.exists "#{req.params.domain}.rb#{v[0]}"

  db.exec (e, r) ->
    if e
      return res.status(500).json error: 'db_error'

    for v in r
      if r[1] is 0
        return res.status(400).json error: 'bad_rid'

    db.multi()

    for v in rids
      db.sadd "#{req.params.domain}.rf#{v[0]}", req.body.email
      db.zadd "#{req.params.domain}.uf#{req.body.email}", v[1] or 0, v[0]

    db.exec (e, r) ->
      if e
        return res.status(500).json error: 'db_error'

      return res.status(500).json result: 'OK'


app.use '/static', express.static '/public'

app.get '/:domain', (req, res) ->
  db.sismember 'd', req.params.domain, (e, r) ->
    if e
      return res.status(500).sendfile '/public/500.html'
 
    if r
      res.sendfile '/public/app.html'
 
    else
      res.status(404).sendfile '/public/bad_domain.html'
 
app.get '/', (req, res) ->
  res.sendfile '/public/index.html'

app.listen process.env.PORT or config.DEFAULT_PORT or 80
