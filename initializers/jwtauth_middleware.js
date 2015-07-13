module.exports = {
  initialize: function( api, next ){

    var jwtauth_middleware = {

     name: 'jwtauth simple',
      global: true,
      priority: 10,
      preProcessor: function(data, next){

        if(data.actionTemplate.authenticated === true 
         && api.config.jwtauth.enabled[data.connection.type] 
         && api.config.jwtauth.enabled[data.connection.type] === true) {
         console.log('starting jwtquc');
          var req = data.connection.rawConnection.req;
          if(!req && data.connection.mockHeaders) {
            req = {
              headers: data.connection.mockHeaders
            };
          } else { //this needs rethinking
            req = {
              headers: {}
            };
          }
          if(req.headers && req.headers['authorization']) {
            var parts = req.headers['authorization'].split(' ');
            if(parts.length != 2) {
              data.connection.rawConnection.responseHttpCode = 500;
              //data.connection.
              error = {
                code: 500,
                message: 'Invalid Authorization Header'
              };
              next(error);
            } else {
              if(parts[0].toLowerCase() != 'token') {
                data.connection.rawConnection.responseHttpCode = 500;
              //data.connection.
                error = {              
                  code: 500,
                  message: 'Invalid Authorization Header'
                };
                next(error);
              } else {
                api.jwtauth.processToken(parts[1], function(jdata) {
                  // Valid data, lets set it and continue
                  console.log('setting user for token');
                  data.connection.user = jdata;
                  data.params.jwtuser = jdata;
                  next();
                }, function(err) {
                  data.connection.rawConnection.responseHttpCode = err.http_status;
                  delete err.http_status;
                  //data.connection.
                  error = err;
                  next(error);
                });
              }
            } 
          } else if (data.params.token){
            console.log('token param found in middleware');
                api.jwtauth.processToken(data.params.token, function(jdata) {
                  // Valid data, lets set it and continue
                  data.connection.user = jdata;
                  data.connection.rawConnection.user = jdata
                  data.params.jwtuser = jdata;
                  next();
                }, function(err) {
                  data.connection.rawConnection.responseHttpCode = err.http_status;
                  delete err.http_status;
                  //data.connection.
                  error = err;
                  next(error);
                });          
          
          } else {
              data.connection.rawConnection.responseHttpCode = 500;
              //data.connection.
              error = {
                code: 500,
                message: 'Authorization Header Not Set'
              };
              next(error);
          }
        } else {
          next();
        }
      }

      /*
        postProcessor: function(data, next){
          //just a placeholder
      }
      */
    }
     api.actions.addMiddleware(jwtauth_middleware);

      next();

    
  },
};