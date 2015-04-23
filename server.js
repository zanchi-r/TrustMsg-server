var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/trustmsg');
var db = mongoose.connection;
var crypto = require('crypto');

var loggedUsers = {};

function disconnect(user) {
  console.log('user disconnected ' + user);
  if (loggedUsers[user])
    delete loggedUsers[user];
}

function generatePasswordHash(password) {
  return (crypto.createHash('sha256').update(password).digest('hex'));
}

function createAccount(username, password, socket) {
  if (username && password) {
    User.findOne({'username': username}).exec(function(err, user) {
      if (user) {
        socket.emit('create_account_response', {
          'result': 'ko',
          'error': 'username already exists'
        });
      }
      else {
        var user = new User({'username': username, 'password': generatePasswordHash(password)});
        user.save(function(err, user) {
          if (err) {
            socket.emit('create_account_response', {
              'result': 'ko',
              'error': 'cannot save to db'
            });
          }
          else {
            socket.emit('create_account_response', {
              'result': 'ok'
            });
          }
        });
      }
    });
  }
  else
  {
    socket.emit('create_account_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function loginUser(username, password, socket) {
  if (username && password)
  {
    User.findOne({'username': username}).exec(function(err, user) {
      if (user) {
        if (user.password == generatePasswordHash(password)) {
          if (user.isLogged()) {
            socket.emit('login_response', {
              'result': 'ko',
              'error': 'already logged in'
            });
          }
          else {
            loggedUsers[username] = socket;
            socket.emit('login_response', {
              'result': 'ok'
            });
          }
        }
        else {
          socket.emit('login_response', {
            'result': 'ko',
            'error': 'invalid password'
          });
        }
      }
      else {
        socket.emit('login_response', {
          'result': 'ko',
          'error': 'user does not exist'
        });
      }
    });
  }
  else {
    socket.emit('login_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function savePublicKey(username, key, socket) {
  if (username && key){
    User.findOne({'username': username}).exec(function(err, user) {
      if (user) {
        user.public_key = key;
        user.save(function(err, user) {
          if (err) {
            socket.emit('save_public_key_response', {
              'result': 'ko',
              'error': 'cannot save to db'
            });
          }
          else {
            socket.emit('save_public_key_response', {
              'result': 'ok'
            });
          }
        });
      }
      else {
        socket.emit('save_public_key_response', {
          'result': 'ko',
          'username': username,
          'error': 'cannot find user'
        });
      }
    });
  }
  else {
    socket.emit('save_public_key_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function getPublicKey(username, socket) {
  if (username) {
    User.findOne({'username': username}).exec(function(err, user) {
      if (user) {
        if (user.public_key) {
          socket.emit('get_public_key_response', {
            'result': 'ok',
            'username': username,
            'key': user.public_key
          });
        }
        else {
          socket.emit('get_public_key_response', {
            'result': 'ko',
            'username': username,
            'error': 'user exists but does not have a key'
          });
        }
      }
      else {
        socket.emit('get_public_key_response', {
          'result': 'ko',
          'username': username,
          'error': 'cannot find user'
        });
      }
    });
  }
  else {
    socket.emit('get_public_key_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function getStatus(username, socket) {
  if (username) {
    var status;
    if (loggedUsers[username])
      status = "online";
    else
      status = "offline";
    socket.emit('get_status_response', {
      'result': 'ok',
      'username': username,
      'status': status
    });
  }
  else {
    socket.emit('get_status_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function sendMessage(usernameFrom, usernameTo, message, socket) {
  var now = Date.now();
  if (usernameFrom && usernameTo && message) {
    if (loggedUsers[usernameTo]) {
      socket.emit('message_received', {
        'usernameFrom': usernameFrom,
        'usernameTo': usernameTo,
        'date': now,
        'message': message
      });
      socket.emit('send_message_response', {
        'result': 'ok',
        'status': 'online',
        'usernameFrom': usernameFrom,
        'usernameTo': usernameTo,
        'date': now,
        'message': message
      });
    }
    else {
      User.findOne({'username': usernameTo}).exec(function(err, user) {
        if (user) {
          user.messages.push({'usernameFrom':usernameFrom,
                              'usernameTo':usernameTo,
                              'date': now,
                              'message': message});
          user.save();
          socket.emit('send_message_response', {
            'result': 'ok',
            'status': 'offline',
            'usernameFrom': usernameFrom,
            'usernameTo': usernameTo,
            'date': now,
            'message': message
          });
        }
        else {
          socket.emit('send_message_response', {
            'result': 'ko',
            'usernameFron': usernameFrom,
            'username': usernameTo,
            'message': message,
            'error': 'cannot find user'
          });
        }
      });
    }
  }
  else {
    socket.emit('send_message_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function getMessages(username, socket) {
  User.findOne({'username': username}).exec(function(err, user) {
    if (user) {
      user.messages.forEach(function (message) {
        socket.emit('message_received', message);
      });
      user.messages = [];
      user.save();
    }
    else {
      socket.emit('get_messages_response', {
        'result': 'ko',
        'error': 'cannot find user'
      });
    }
  });
}

io.on('connection', function(socket){
  var username;

  socket.on('create_account', function(data) {
    createAccount(data.username, data.password, socket);
  });

  socket.on('login', function(data) {
    loginUser(data.username, data.password, socket);
    username = data.username;
    socket.on('save_public_key', function(data) {
      savePublicKey(username, data.key, socket);
    });
    socket.on('get_public_key', function(data) {
      getPublicKey(data.username, socket);
    });
    socket.on('get_status', function(data) {
      getStatus(data.username, socket);
    });
    socket.on('send_message', function(data) {
      sendMessage(username, data.username, data.message, socket);
    });
    socket.on('get_messages', function(data) {
      getMessages(username, socket);
    });
    socket.on('create_group', function(data) {

    });
  });

  socket.on('disconnect', function(){
    disconnect(username);
  });
});

http.listen(8000, function(){
  console.log('listening on *:8000');
});

db.on('error', function() {
  console.log("Can't connect to mongodb");
  process.exit(1);
});
db.once('open', function (callback) {
});

var UserSchema = mongoose.Schema({
  username: String,
  password: String,
  public_key: String,
  messages: Array
});

UserSchema.methods.isLogged = function() {
  return (this.username in loggedUsers);
}

var User = mongoose.model('User', UserSchema);
