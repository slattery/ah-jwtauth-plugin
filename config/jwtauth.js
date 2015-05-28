exports.default = { 
  jwtauth: function(api){
    return {
      enabled: {
        web: true,
        websocket: true,
        socket: false,
        testServer: false
      },
      secret: 'changeme',
      algorithm: 'HS512'
    }
  }
}

exports.test = { 
  jwtauth: function(api){
    return {
      enabled: {
        web: false,
        websocket: false,
        socket: false,
        testServer: false
      },
      secret: 'changeme',
      algorithm: 'HS512'
    }
  }
}

exports.production = { 
  jwtauth: function(api){
    return {
      enabled: {
        web: true,
        websocket: true,
        socket: false,
        testServer: false
      },
      secret: 'changeme',
      algorithm: 'HS512'
    }
  }
}

exports.singlebox = { 
  jwtauth: function(api){
    return {
      enabled: {
        web: true,
        websocket: true,
        socket: false,
        testServer: false
      },
      secret: 'good food is better than fake food',
      algorithm: 'HS512'
    }
  }
}