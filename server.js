var fs = require('fs');
var app = require('express')();
var https = require('https');
var server = https.createServer({key: fs.readFileSync('./config/ssl.key'), cert: fs.readFileSync('./config/ssl.cert'), passphrase: 'trustmsg'}, app);
var io = require('socket.io').listen(server);
var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/trustmsg');
var mongooseIdToken = require('mongoose-id-token');
var db = mongoose.connection;
var crypto = require('crypto');
var async = require("async");


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
        if (user.validPassword(password)) {
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

function sendMessage(usernameFrom, usernameTo, groupTo, message, socket) {
  var now = Date.now();
  if (usernameFrom && (usernameTo || groupTo) && message) {
    if (groupTo) {
      Group.findOne({'_id': groupTo}).exec(function(err, group) {
        if (group && group.userInGroup(usernameFrom)) {
          group.users.forEach(function(username) {
            User.findOne({'username': username}).exec(function(err, user) {
              if (user && username != usernameFrom) {
                user.sendMessage(usernameFrom, groupTo, username, message, now, false, socket);
              }
            });
          });
        }
        else if (group) {
          socket.emit('send_message_response', {
            'result': 'ko',
            'usernameFrom': usernameFrom,
            'groupTo': groupTo,
            'message': message,
            'error': 'permission denied'
          });
        }
        else {
          socket.emit('send_message_response', {
            'result': 'ko',
            'usernameFrom': usernameFrom,
            'groupTo': groupTo,
            'message': message,
            'error': 'cannot find group'
          });
        }
      });
    }
    else {
      User.findOne({'username': usernameTo}).exec(function(err, user) {
        if (user) {
          user.sendMessage(usernameFrom, undefined, usernameTo, message, now, true, socket);
        }
        else {
          socket.emit('send_message_response', {
            'result': 'ko',
            'usernameFrom': usernameFrom,
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
      user.messages.forEach(function(message) {
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

function createGroup(name, usernames, socket) {
  if (name && usernames) {
    var calls = [];
    var users = [];
    var failedUsers = [];

    usernames.forEach(function(username) {
      if (users.indexOf(username) == -1) {
        calls.push(function(callback) {
          User.findOne({'username': username}).exec(function(err, user) {
            if (user)
            users.push(username);
            else
            failedUsers.push(username);
            callback(null, username);
          });
        });
      }
    });

    async.parallel(calls, function(err, result) {

      var group = new Group({'name': name, 'users': users});

      group.save(function(err, group) {
        if (err) {
          socket.emit('create_group_response', {
            'result': 'ko',
            'name': group.name,
            'error': 'cannot save to db'
          });
        }
        else {
          socket.emit('create_group_response', {
            'result': 'ok',
            'groupID': group._id,
            'name': group.name,
            'users': users,
            'failedUsers': failedUsers
          });
        }
      });
    });
  }
  else {
    socket.emit('create_group_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function addUserToGroup(groupID, usernameToAdd, username, socket) {
  if (groupID && usernameToAdd) {
    User.findOne({'username': usernameToAdd}).exec(function(err, user) {
      if (user) {
        Group.findOne({'_id': groupID}).exec(function(err, group) {
          if (group && !group.userInGroup(username)) {
            socket.emit('add_user_to_group_response', {
              'result': 'ko',
              'groupID': groupID,
              'username': usernameToAdd,
              'error': "permission denied"
            });
          }
          else if (group && group.userInGroup(usernameToAdd)) {
            socket.emit('add_user_to_group_response', {
              'result': 'ko',
              'groupID': groupID,
              'username': usernameToAdd,
              'error': "user already in group"
            });
          }
          else if (group) {
            group.addUser(usernameToAdd);
            group.save(function(err, group) {
              if (err) {
                socket.emit('add_user_to_group_response', {
                  'result': 'ko',
                  'groupID': groupID,
                  'username': usernameToAdd,
                  'error': "cannot save to db"
                });
              }
              else {
                socket.emit('add_user_to_group_response', {
                  'result': 'ok',
                  'groupID': groupID,
                  'username': usernameToAdd,
                  'users': group.users
                });
              }
            });
          }
          else {
            socket.emit('add_user_to_group_response', {
              'result': 'ko',
              'groupID': groupID,
              'username': usernameToAdd,
              'error': "cannot find group"
            });
          }
        });
      }
      else {
        socket.emit('add_user_to_group_response', {
          'result': 'ko',
          'groupID': groupID,
          'username': usernameToAdd,
          'error': "cannot find user"
        });
      }
    });
  }
  else {
    socket.emit('add_user_to_group_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function removeUserFromGroup(groupID, usernameToRemove, username, socket) {
  if (groupID && usernameToRemove) {
    Group.findOne({'_id': groupID}).exec(function(err, group) {
      if (group && !group.userInGroup(username)) {
        socket.emit('remove_user_from_group_response', {
          'result': 'ko',
          'groupID': groupID,
          'username': usernameToRemove,
          'error': "permission denied"
        });
      }
      else if (group && group.userInGroup(usernameToRemove)) {
        group.removeUser(usernameToRemove);
        group.save(function(err, group) {
          if (err) {
            socket.emit('remove_user_from_group_response', {
              'result': 'ko',
              'groupID': group._id,
              'username': usernameToRemove,
              'error': 'cannot save to db'
            });
          }
          else {
            socket.emit('remove_user_from_group_response', {
              'result': 'ok',
              'groupID': group._id,
              'username': usernameToRemove,
              'users': group.users
            });
          }
        });
      }
      else if (group) {
        socket.emit('remove_user_from_group_response', {
          'result': 'ko',
          'groupID': groupID,
          'username': usernameToRemove,
          'error': "user not in group"
        });
      }
      else {
        socket.emit('remove_user_from_group_response', {
          'result': 'ko',
          'groupID': groupID,
          'username': usernameToRemove,
          'error': "cannot find group"
        });
      }
    });
  }
  else {
    socket.emit('remove_user_from_group_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function getGroupList(username, socket) {
  Group.find({}).exec(function(err, groups) {
    if (err) {
      socket.emit('get_group_list_response', {
        'result': 'ko',
        'error': 'cannot get group list'
      });
    }
    else {
      var userGroups = [];
      groups.forEach(function(group) {
        if (group.userInGroup(username)) {
          userGroups.push({'groupID': group._id, 'name': group.name, 'users': group.users});
        }
      });
      socket.emit('get_group_list_response', {
        'result': 'ok',
        'groups': userGroups
      })
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
      sendMessage(username, data.username, data.groupID, data.message, socket);
    });
    socket.on('get_messages', function(data) {
      getMessages(username, socket);
    });
    socket.on('create_group', function(data) {
      createGroup(data.name, data.usernames, socket);
    });
    socket.on('add_user_to_group', function(data) {
      addUserToGroup(data.groupID, data.username, username, socket);
    });
    socket.on('remove_user_from_group', function(data) {
      removeUserFromGroup(data.groupID, data.username, username, socket);
    });
    socket.on('get_group_list', function(data) {
      getGroupList(username, socket);
    });
  });

  socket.on('disconnect', function(){
    disconnect(username);
  });
});

server.listen(8000, function(){
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

UserSchema.methods.validPassword = function(password) {
  return (this.password == generatePasswordHash(password));
}

UserSchema.methods.isLogged = function() {
  return (this.username in loggedUsers);
}

UserSchema.methods.addMessage = function(usernameFrom, usernameTo, date, message) {
  this.messages.push({'usernameFrom':usernameFrom,
  'usernameTo':usernameTo,
  'date': date,
  'message': message});
}

UserSchema.methods.sendMessage = function(usernameFrom, groupID, usernameTo, message, date, sendResponse, socket) {
  if (loggedUsers[usernameTo]) {
    socket.emit('message_received', {
      'usernameFrom': usernameFrom,
      'groupID': groupID,
      'usernameTo': usernameTo,
      'date': date,
      'message': message
    });
    if (sendResponse) {
      socket.emit('send_message_response', {
        'result': 'ok',
        'status': 'online',
        'usernameFrom': usernameFrom,
        'groupID': groupID,
        'usernameTo': usernameTo,
        'date': date,
        'message': message
      });
    }
  }
  else {
    this.addMessage(usernameFrom, usernameTo, date, message);
    this.save(function(err, user) {
      if (sendResponse) {
        if (err) {
          socket.emit('send_message_response', {
            'result': 'ko',
            'usernameFrom': usernameFrom,
            'groupID': groupID,
            'username': usernameTo,
            'message': message,
            'date': date,
            'error': 'cannot save to db'
          });
        }
        else {
          socket.emit('send_message_response', {
            'result': 'ok',
            'status': 'offline',
            'usernameFrom': usernameFrom,
            'groupID': groupID,
            'usernameTo': usernameTo,
            'date': date,
            'message': message
          });
        }
      }
    });
  }
}

var User = mongoose.model('User', UserSchema);

var GroupSchema = mongoose.Schema({
  name: String,
  users: Array
});

GroupSchema.methods.userInGroup = function(username) {
  return (this.users.indexOf(username) > -1);
}

GroupSchema.methods.addUser = function(username) {
  if (!this.userInGroup(username))
  this.users.push(username);
}

GroupSchema.methods.removeUser = function(username) {
  var index = this.users.indexOf(username);
  if (index !== -1) {
    this.users.splice(index, 1);
  }
}

var Group = mongoose.model('Group', GroupSchema);
GroupSchema.plugin(mongooseIdToken)
