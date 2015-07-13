var jsonwebtoken = require ('jsonwebtoken');

module.exports = {
  loadPriority:  100,
  startPriority: 100,
  stopPriority:  1000,

  initialize: function(api, next){

    api.jwtauth = {
      // success and fail cb are in the middleware
      processToken: function(token, success, fail) {
        var secret = 'good food is better than fake food';
        console.log('processing token');
        if ( api.config.jwtauth && api.config.jwtauth.secret ){
          secret = api.config.jwtauth.secret;
        }     
      
        jsonwebtoken.verify(token, secret, {}, function(err, data) {
          if(err) {
            fail(err);
          } else {
            success(data);
          }
        });
      },
      
      generateToken: function(data, success, fail) {
        try {
          var secret = 'good food is better than fake food';
          if ( api.config.jwtauth && api.config.jwtauth.secret ){
            secret = api.config.jwtauth.secret;
          }
          var algorithm = 'RS512';
          if ( api.config.jwtauth && api.config.jwtauth.algorithm ){
            algorithm = api.config.jwtauth.algorithm;
          }
          var token = jsonwebtoken.sign(data, secret, {
            algorithm: algorithm
          });
          success(token);
        } catch(err) {
          fail(err);
        }
      }
    };
    next();
  },
  start: function(api, next){
    // connect to server
    next();
  },
  stop: function(api, next){
    // disconnect from server
    next();
  }
}