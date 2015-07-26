# USEFUL DEFINITIONS

  sub = (module, args) ->
    module.view.bind this, new module.controller args


  falsy = ->
    return false


  page = {}
  com = {}


# HEADER COMPONENT

  com.header = {}


  com.header.model =
    results: m.prop []


  com.header.model.search = (e) ->
    m.request
      method: 'get'
      url: '/api/search/'
      data: q: e.target.value
    .then (res) ->
      @results if res.done then res.done else [res.error]

    return


  com.header.controller = (args) ->
    @model = new com.header.model

    return


  com.header.view = (ctrl) -> 
    m 'header .pure-g',
      m '.pure-u',
        m '.pure-menu .pure-menu-horizontal',
          m 'a .pure-menu-heading .pure-menu-link [href="/"]',
            config: m.route,
            m.trust '<svg></svg>'
          
          m '.float-right',
            m '.pure-menu-item',
              m 'a .pure-menu-link [href="/add"]',
                config: m.route,
                m.trust '<svg></svg>'
            
            m '.pure-menu-item .pure-menu-has-children .pure-menu-allow-hover',
              m 'input .search [type="text"]',
                onchange: ctrl.model.search.bind this
              
              m 'ul .pure-menu-children',
                ctrl.model.results().map (v) ->
                  m 'li .pure-menu-item',
                    m "a .pure-menu-link [href=\"#{v.link}\"]",
                      v.title


# SIDEBAR COMPONENT

  com.sidebar = {}


  com.sidebar.model =
    pages:
      'Home': 
        path: '/'
        notifications: m.prop false
      'Events':
        path: '/events'
        notifications: m.prop false
      'Cadet Scores'
        path: '/scores'
        notifications: m.prop false
      'Reports'
        path: '/reports'
        notifications: m.prop false
      'MVC Nominations'
        path: '/mvc'
        notifications: m.prop false


  com.sidebar.controller = (args) ->
    @model = new com.sidebar.model

    return


  com.sidebar.view = (ctrl) ->
    m 'nav .pure-u .sidebar'
      m '.pure-menu',
        m 'ul .pure-menu-list',
          Object.keys(ctrl.model.pages).map (v) ->
            m 'li .pure-menu-item',
              m "a [href=\"#{ctrl.model.pages(v).path}\"]",
                config: m.route,
                v
              if ctrl.model.pages(v).notifications()
                m.trust '<svg class="float-right"></svg>'

        m 'h2',
          m 'small', ctrl.model.greeting()
          m 'br'
          @ctrl.model.name()

        m 'ul.pure-menu-list',
          m 'li .pure-menu-item',
            m 'a [href="/settings"]',
              config: m.route,
              'Settings'

          m 'li .pure-menu-item',
            m 'a [href="/logout"]',
              config: m.route


# 


# MAIN PAGE

  page.home = {}


  page.home.model = {}


# ROUTING

  header = sub com.header
  sidebar = sub com.sidebar


  lay = (page) ->
    p = new page
    
    model: p.model
    controller: p.controller
    view: -> [
      header()

      m 'pure-g',
        sidebar()

        p.view()
    ]


  m.route document.body, '/',
    '/':          lay page.home
    '/events':    lay page.events
    '/scores':    lay page.scores
    '/reports':   lay page.reports
    '/mvc':       lay page.mvc
    '/settings':  lay page.settings
