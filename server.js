/*
** Load some modules
*/
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

// Logged users and their socket are stored here
var loggedUsers = {};

/*
** Disconnect a user
** This function is called when a socket connection is closed
** Params:
**   - user : The username
*/
function disconnect(user) {
  console.log('user disconnected ' + user);
  // Remove the user from the logged users list
  if (loggedUsers[user])
    delete loggedUsers[user];
}

/*
** Generate a password hash
** Params:
**   - password: Plain text password
** Returns: A sha256 hash
*/
function generatePasswordHash(password) {
  return (crypto.createHash('sha256').update(password).digest('hex'));
}

/*
** Create a user account
** Params:
**   - username: The username
**   - password: The plain text password
**   - socket: The socket associated to the connected user
*/
function createAccount(username, password, socket) {
  if (username && password) {
    // Try to find an existing user in DB with this username
    User.findOne({'username': username}).exec(function(err, user) {
      if (user) {
        // Send an error if the username already exists
        socket.emit('create_account_response', {
          'result': 'ko',
          'error': 'username already exists'
        });
      }
      else {
        // Create a user and save it
        var user = new User({'username': username, 'password': generatePasswordHash(password)});
        user.save(function(err, user) {
          if (err) {
            // Send an error to the user on database error
            socket.emit('create_account_response', {
              'result': 'ko',
              'error': 'cannot save to db'
            });
          }
          else {
            // Send a confirmation
            socket.emit('create_account_response', {
              'result': 'ok',
              'username': username
            });
          }
        });
      }
    });
  }
  else
  {
    // Send an error on invalid request
    socket.emit('create_account_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Log a user in
** Params:
**   - username: The username
**   - password: The plain text password
**   - socket: The socket associated to the connected user
*/
function loginUser(username, password, socket) {
  if (username && password)
  {
    // Try to find the user in DB
    User.findOne({'username': username}).exec(function(err, user) {
      if (user) {
        // If the user exists, check if the password is valid
        if (user.validPassword(password)) {
          if (user.isLogged()) {
            // Send an error if the user is already logged
            socket.emit('login_response', {
              'result': 'ko',
              'error': 'already logged in'
            });
          }
          else {
            // Add the user to the logged users list
            loggedUsers[username] = socket;
            // Send a login confirmation
            socket.emit('login_response', {
              'result': 'ok',
              'username': username
            });
          }
        }
        else {
          // Send an error if the password is not valid
          socket.emit('login_response', {
            'result': 'ko',
            'error': 'invalid password'
          });
        }
      }
      else {
        // Send an error if the user does not exists
        socket.emit('login_response', {
          'result': 'ko',
          'error': 'user does not exist'
        });
      }
    });
  }
  else {
    // Send an error on invalid request
    socket.emit('login_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Upload a public key for a given user
** Params:
**   - username: The username of the logged user
**   - key: The public key
**   - socket: The socket associated to the logged user
*/
function savePublicKey(username, key, socket) {
  if (username && key){
    // Try to find the user in DB
    User.findOne({'username': username}).exec(function(err, user) {
      if (user) {
        // If the user exists, save the key
        user.public_key = key;
        user.save(function(err, user) {
          if (err) {
            // Send an error to the user on database error
            socket.emit('save_public_key_response', {
              'result': 'ko',
              'error': 'cannot save to db'
            });
          }
          else {
            // Send a confirmation to the user
            socket.emit('save_public_key_response', {
              'result': 'ok'
            });
          }
        });
      }
      else {
        // Send an error if the user does not exists
        socket.emit('save_public_key_response', {
          'result': 'ko',
          'username': username,
          'error': 'cannot find user'
        });
      }
    });
  }
  else {
    // Send an error on invalid request
    socket.emit('save_public_key_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Get the public key of a given user
** Params:
**   - username: The username of the logged user
**   - socket: The socket associated to the logged user
*/
function getPublicKey(username, socket) {
  if (username) {
    // Try to find the user in DB
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
          // Send an error if the user does not have a public key
          socket.emit('get_public_key_response', {
            'result': 'ko',
            'username': username,
            'error': 'user exists but does not have a key'
          });
        }
      }
      else {
        // Send an error if the user does not exists
        socket.emit('get_public_key_response', {
          'result': 'ko',
          'username': username,
          'error': 'cannot find user'
        });
      }
    });
  }
  else {
    // Send an error on invalid request
    socket.emit('get_public_key_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Get the status (online/offline) of a given user
** Params:
**   - username: The username of the logged user
**   - socket: The socket associated to the logged user
*/
function getStatus(username, socket) {
  if (username) {
    var status;
    // Check if the user is logged
    if (loggedUsers[username])
      status = "online";
    else
      status = "offline";
    // Send the response
    socket.emit('get_status_response', {
      'result': 'ok',
      'username': username,
      'status': status
    });
  }
  else {
    // Send an error on invalid request
    socket.emit('get_status_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

function keyExchange(usernameFrom, usernameTo, groupID, groupName, senderPublicKey, key, socket) {
  if (usernameFrom && (usernameTo || groupID) && key) {
    if (groupID) {
      Group.findOne({'_id': groupID}).exec(function(err, group) {
        // TODO
      });
    }
    else {
      // Try to find the user
      User.findOne({'username': usernameTo}).exec(function(err, user) {
        if (user) {
          // If the user exists, send the key
          user.sendKeyExchange(usernameFrom, usernameTo, groupID, groupName, senderPublicKey, key, false, socket);
        }
        else {
          // Send an error if the user does not exists
          socket.emit('key_exchange_response', {
            'result': 'ko',
            'usernameFrom': usernameFrom,
            'username': usernameTo,
            'senderPublicKey': senderPublicKey,
            'key': key,
            'error': 'cannot find user'
          });
        }
      });
    }
  }
  else {
    // Send an error on invalid request
    socket.emit('key_exchange_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Get key exchanges
** Params:
**   - username: The username of the logged user
**   - socket: The socket associated to the logged user
*/
function getKeyExchanges(username, socket) {
  // Try to find the user in DB
  User.findOne({'username': username}).exec(function(err, user) {
    if (user) {
      // If the user exists, send all the key exchanges
      user.key_exchanges.forEach(function(keyExchange) {
        socket.emit('key_exchange_received', keyExchange);
      });
      // Delete all exchanges and save
      user.key_exchanges = [];
      user.save();
    }
    else {
      // Send an error if the user does not exists
      socket.emit('get_response', {
        'result': 'ko',
        'error': 'cannot find user'
      });
    }
  });
}

/*
** Send a message to a user or a group
** Params:
**   - usernameFrom: The sender's username
**   - usernameTo: The receiver's username. Set to undefined for a group message
**   - groupTo: ID of a group. Set to undefined if it's not a group message
**   - message: The encrypted message
**   - socket: The socket associated to the logged user
*/
function sendMessage(usernameFrom, usernameTo, groupTo, message, socket) {
  var now = Date.now();
  if (usernameFrom && (usernameTo || groupTo) && message) {
    if (groupTo) {
      // If it's a group message, try to find the group in DB
      Group.findOne({'_id': groupTo}).exec(function(err, group) {
        if (group && group.userInGroup(usernameFrom)) {
          // Try to find each user of the group in the DB
          group.users.forEach(function(username) {
            User.findOne({'username': username}).exec(function(err, user) {
              if (user && username != usernameFrom) {
                // If the user exists and is not the sender, send the message
                user.sendMessage(usernameFrom, groupTo, group.name, username, message, now, false, socket);
              }
            });
          });
        }
        else if (group) {
          // Send an error if the user does not belong to the group
          socket.emit('send_message_response', {
            'result': 'ko',
            'usernameFrom': usernameFrom,
            'groupTo': groupTo,
            'message': message,
            'error': 'permission denied'
          });
        }
        else {
          // Send an error if it's a group message and the group does not exists
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
      // If it's not a group message, try to find the user
      User.findOne({'username': usernameTo}).exec(function(err, user) {
        if (user) {
          // If the user exists, send the message
          user.sendMessage(usernameFrom, undefined, undefined, usernameTo, message, now, true, socket);
        }
        else {
          // Send an error if the user does not exists
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
    // Send an error on invalid request
    socket.emit('send_message_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Get received messages
** Params:
**   - username: The username of the logged user
**   - socket: The socket associated to the logged user
*/
function getMessages(username, socket) {
  // Try to find the user in DB
  User.findOne({'username': username}).exec(function(err, user) {
    if (user) {
      // If the user exists, send all the messages
      user.messages.forEach(function(message) {
        socket.emit('message_received', message);
      });
      // Delete all messages and save
      user.messages = [];
      user.save();
    }
    else {
      // Send an error if the user does not exists
      socket.emit('get_messages_response', {
        'result': 'ko',
        'error': 'cannot find user'
      });
    }
  });
}

/*
** Create a group
** Params:
**   - name: The name of the group
**   - usernames: An array of usernames. The creator of the group must be in the array
**   - socket: The socket associated to the logged user
*/
function createGroup(name, usernames, socket) {
  if (name && usernames) {
    var calls = [];
    var users = [];
    var failedUsers = [];

    // Iterate on all the usernames
    usernames.forEach(function(username) {
      // Check that the user is not already in the group
      if (users.indexOf(username) == -1) {
        // Create a list of calls to run in parallel
        // We run it this way because DB queries are asynchronous and we need to wait for the result
        calls.push(function(callback) {
          // Try to find the username in database
          User.findOne({'username': username}).exec(function(err, user) {
            // If the user exists, add it in the user list
            if (user)
              users.push(username);
            // If the user do not exists, add it in the list of users that can't be added
            else
              failedUsers.push(username);
            callback(null, username);
          });
        });
      }
    });

    // Run all the calls in parallel
    async.parallel(calls, function(err, result) {
      // Create a new group
      var group = new Group({'name': name, 'users': users});
      // Save it in DB
      group.save(function(err, group) {
        if (err) {
          // Send an error to the user on database error
          socket.emit('create_group_response', {
            'result': 'ko',
            'name': group.name,
            'error': 'cannot save to db'
          });
        }
        else {
          // On success, send a response with all the group informations
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
    // Send an error on invalid request
    socket.emit('create_group_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Add a user to a group
** Params:
**   - groupID: The group ID
**   - groupName: The group name
**   - usernameToAdd: The username to add
**   - username: The username of the logged user
**   - socket: The socket associated to the logged user
*/
function addUserToGroup(groupID, groupName, usernameToAdd, username, socket) {
  if (groupID && groupName && usernameToAdd) {
    // Try to find the user in DB
    User.findOne({'username': usernameToAdd}).exec(function(err, user) {
      if (user) {
        // If the user exists, try to find the group
        Group.findOne({'_id': groupID}).exec(function(err, group) {
          if (group && !group.userInGroup(username)) {
            // Send an error if the logged user does not belong to the group
            socket.emit('add_user_to_group_response', {
              'result': 'ko',
              'groupID': groupID,
              'groupName': groupName,
              'username': usernameToAdd,
              'error': "permission denied"
            });
          }
          else if (group && group.userInGroup(usernameToAdd)) {
            // Send an error if the user to add is already in the group
            socket.emit('add_user_to_group_response', {
              'result': 'ko',
              'groupID': groupID,
              'groupName': groupName,
              'username': usernameToAdd,
              'error': "user already in group"
            });
          }
          else if (group) {
            // If the user exists and is not in the group, add the user
            group.addUser(usernameToAdd);
            // Save the group infos
            group.save(function(err, group) {
              if (err) {
                // Send an error to the user on database error
                socket.emit('add_user_to_group_response', {
                  'result': 'ko',
                  'groupID': groupID,
                  'groupName': groupName,
                  'username': usernameToAdd,
                  'error': "cannot save to db"
                });
              }
              else {
                // Send a confirmation on success
                socket.emit('add_user_to_group_response', {
                  'result': 'ok',
                  'groupID': groupID,
                  'groupName': groupName,
                  'username': usernameToAdd,
                  'users': group.users
                });
              }
            });
          }
          else {
            // Send an error if he group does not exists
            socket.emit('add_user_to_group_response', {
              'result': 'ko',
              'groupID': groupID,
              'groupName': groupName,
              'username': usernameToAdd,
              'error': "cannot find group"
            });
          }
        });
      }
      else {
        // Send an error if the user does not exists
        socket.emit('add_user_to_group_response', {
          'result': 'ko',
          'groupID': groupID,
          'groupName': groupName,
          'username': usernameToAdd,
          'error': "cannot find user"
        });
      }
    });
  }
  else {
    // Send an error on invalid request
    socket.emit('add_user_to_group_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Remove a user from a group
** Params:
**   - groupID: The group ID
**   - groupName: The group name
**   - usernameToAdd: The username to add
**   - username: The username of the logged user
**   - socket: The socket associated to the logged user
*/
function removeUserFromGroup(groupID, groupName, usernameToRemove, username, socket) {
  if (groupID && groupName && usernameToRemove) {
    // Try to find the user in DB
    Group.findOne({'_id': groupID}).exec(function(err, group) {
      if (group && !group.userInGroup(username)) {
        // Send an error if the user does not belong to the group
        socket.emit('remove_user_from_group_response', {
          'result': 'ko',
          'groupID': groupID,
          'groupName': groupName,
          'username': usernameToRemove,
          'error': "permission denied"
        });
      }
      else if (group && group.userInGroup(usernameToRemove)) {
        // If the user exists and is in the group, remove the user
        group.removeUser(usernameToRemove);
        // Save the group infos
        group.save(function(err, group) {
          if (err) {
            // Send an error to the user on database error
            socket.emit('remove_user_from_group_response', {
              'result': 'ko',
              'groupID': group._id,
              'groupName': groupName,
              'username': usernameToRemove,
              'error': 'cannot save to db'
            });
          }
          else {
            // Send a confirmation on success
            socket.emit('remove_user_from_group_response', {
              'result': 'ok',
              'groupID': group._id,
              'groupName': groupName,
              'username': usernameToRemove,
              'users': group.users
            });
          }
        });
      }
      else if (group) {
        // Send an error if the user is not in the group
        socket.emit('remove_user_from_group_response', {
          'result': 'ko',
          'groupID': groupID,
          'groupName': groupName,
          'username': usernameToRemove,
          'error': "user not in group"
        });
      }
      else {
        // Send an error if the group does not exists
        socket.emit('remove_user_from_group_response', {
          'result': 'ko',
          'groupID': groupID,
          'groupName': groupName,
          'username': usernameToRemove,
          'error': "cannot find group"
        });
      }
    });
  }
  else {
    // Send an error on invalid request
    socket.emit('remove_user_from_group_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Get a list of all the groups in which the logged user is located
** Params:
**   - username: The username of the logged user
**   - socket: The socket associated to the logged user
*/
function getGroupList(username, socket) {
  // Get all groups
  Group.find({}).exec(function(err, groups) {

    if (err) {
      // Send an error to the user on database error
      socket.emit('get_group_list_response', {
        'result': 'ko',
        'error': 'cannot get group list'
      });
    }
    else {
      // Array of groups in which the logged user is located
      var userGroups = [];
      groups.forEach(function(group) {
        if (group.userInGroup(username)) {
          // If the logged user is in the group, add it to userGroups
          userGroups.push({'groupID': group._id, 'name': group.name, 'users': group.users});
        }
      });
      // Send the response on success
      socket.emit('get_group_list_response', {
        'result': 'ok',
        'groups': userGroups
      })
    }
  });
}

/*
** Get a list of all the usernames from a group
** Params:
**   - groupID: The group ID
**   - groupName: The group name
**   - username: The username of the logged user
**   - socket: The socket associated to the logged user
*/
function getUsersInGroup(groupID, groupName, username, socket) {
  if (groupID && groupName) {
    // Try to find the group in DB
  Group.findOne({'_id': groupID}).exec(function(err, group) {
    if (group && !group.userInGroup(username)) {
      // Send an error if the user does not belong to the group
      socket.emit('get_users_in_group_response', {
        'result': 'ko',
        'groupID': groupID,
        'groupName': groupName,
        'error': "permission denied"
      });
    }
    else if (group && group.userInGroup(username)) {
      // Send the response on success
      socket.emit('get_users_in_group_response', {
        'result': 'ok',
        'groupID': groupID,
        'groupName': groupName,
        'usernames': group.users
      });
    }
    else {
      // Send an error if the group does not exists
      socket.emit('get_users_in_group_response', {
        'result': 'ko',
        'groupID': groupID,
        'groupName': groupName,
        'error': "cannot find group"
      });
    }
  })
  }
  else {
    // Send an error on invalid request
    socket.emit('get_users_in_group_response', {
      'result': 'ko',
      'error': 'invalid data'
    });
  }
}

/*
** Link socket events to functions
*/
io.on('connection', function(socket){
  var username;
  var firstLogin = true;

  // Link the create_account event to the corresponding function
  // This event is available for everyone
  socket.on('create_account', function(data) {
    createAccount(data.username, data.password, socket);
  });
  // Link the create_account event to the corresponding function
  // This event is available for everyone
  socket.on('login', function(data) {
    loginUser(data.username, data.password, socket);
    // Save the username of the logged user
    username = data.username;
    // All the following events are binded only for logged users on their first login attempt
    if (firstLogin == true) {
      firstLogin = false;
      socket.on('save_public_key', function(data) {
        savePublicKey(username, data.key, socket);
      });
      socket.on('get_public_key', function(data) {
        getPublicKey(data.username, socket);
      });
      socket.on('get_status', function(data) {
        getStatus(data.username, socket);
      });
      socket.on('key_exchange', function(data) {
        keyExchange(username, data.username, data.groupID, data.groupName, data.senderPublicKey, data.key, socket);
      });
      socket.on('get_key_exchanges', function(data) {
        getKeyExchanges(username, socket);
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
        addUserToGroup(data.groupID, data.groupName, data.username, username, socket);
      });
      socket.on('remove_user_from_group', function(data) {
        removeUserFromGroup(data.groupID, data.groupName, data.username, username, socket);
      });
      socket.on('get_group_list', function(data) {
        getGroupList(username, socket);
      });
      socket.on('get_users_in_group', function(data) {
        getUsersInGroup(data.groupID, data.groupName, username, socket);
      });
    }
  });
  // Link the disconnect event to the corresponding function
  // This event is available for everyone
  socket.on('disconnect', function(){
    disconnect(username);
  });
});

/*
** Run the server and listen to the port 8000
*/
server.listen(8000, function(){
  console.log('listening on *:8000');
});

/*
** Close the server on DB error
*/
db.on('error', function() {
  console.log("Can't connect to mongodb");
  process.exit(1);
});
db.once('open', function (callback) {
});

/*
** Mongoose schema for a user
*/
var UserSchema = mongoose.Schema({
  username: String,
  password: String,
  public_key: String,
  messages: Array,
  key_exchanges: Array
});

/*
** Check if the password is valid
** Params:
**   - password: The plain text password
** Returns: true or false
*/
UserSchema.methods.validPassword = function(password) {
  return (this.password == generatePasswordHash(password));
}

/*
** Check if the user is logged
** Returns: true or false
*/
UserSchema.methods.isLogged = function() {
  return (this.username in loggedUsers);
}

UserSchema.methods.addKeyExchange = function(usernameFrom, usernameTo, groupID, groupName, senderPublicKey, key) {
  // Save the key exchange in DB
  this.key_exchanges.push({
    'usernameFrom': usernameFrom,
    'usernameTo': usernameTo,
    'groupID': groupID,
    'groupName': groupName,
    'senderPublicKey': senderPublicKey,
    'key': key
  });
}

/*
** Save a message sent to the user
** Params:
**   - usernameFrom: The sender's username
**   - usernameTo: The receiver's username
**   - date: The date
**   - message: The encrypted message
*/
UserSchema.methods.addMessage = function(usernameFrom, groupID, groupName, usernameTo, date, message) {
  // Save the message in DB
  this.messages.push({
  'usernameFrom':usernameFrom,
  'usernameTo':usernameTo,
  'groupID': groupID,
  'groupName': groupName,
  'date': date,
  'message': message});
}

UserSchema.methods.sendKeyExchange = function(usernameFrom, usernameTo, groupID, groupName, senderPublicKey, key, sendResponse, socket) {
  if (loggedUsers[usernameTo]) {
    loggedUsers[usernameTo].emit('key_exchange_received', {
      'usernameFrom': usernameFrom,
      'usernameTo': usernameTo,
      'groupID': groupID,
      'groupName': groupName,
      'senderPublicKey': senderPublicKey,
      'key': key
    });
    if (sendResponse) {
      socket.emit('key_exchange_response', {
        'result': 'ok',
        'status': 'online',
        'usernameFrom': usernameFrom,
        'usernameTo': usernameTo,
        'groupID': groupID,
        'groupName': groupName,
        'senderPublicKey': senderPublicKey,
        'key': key
      });
    }
  }
  else {
    this.addKeyExchange(usernameFrom, usernameTo, groupID, groupName, senderPublicKey, key);
    this.save(function(err, user) {
      if (err) {
        socket.emit('key_exchange_response', {
          'result': 'ko',
          'usernameFrom': usernameFrom,
          'usernameTo': usernameTo,
          'groupID': groupID,
          'groupName': groupName,
          'key': key,
          'error': 'cannot save to db'
        });
      }
      else {
        socket.emit('key_exchange_response', {
          'result': 'ok',
          'status': 'offline',
          'usernameFrom': usernameFrom,
          'usernameTo': usernameTo,
          'groupID': groupID,
          'groupName': groupName,
          'key': key
        });
      }
    });
  }
}

/*
** Send a message to the user
** Params:
**   - usernameFrom: The sender's username
**   - groupID: ID of the group. Set to undefined if it's not a group message
**   - groupName: Name of the group. Set to undefined if it's not a group message
**   - usernameTo: The receiver's username
**   - message: The encrypted message
**   - date: The date
**   - sendResponse: If true, send a confirmation to the sender
**   - socket: The socket associated to the logged user
*/
UserSchema.methods.sendMessage = function(usernameFrom, groupID, groupName, usernameTo, message, date, sendResponse, socket) {
  if (loggedUsers[usernameTo]) {
    // If the receiver is logged in, send the message directly
    loggedUsers[usernameTo].emit('message_received', {
      'usernameFrom': usernameFrom,
      'groupID': groupID,
      'groupName': groupName,
      'usernameTo': usernameTo,
      'date': date,
      'message': message
    });
    if (sendResponse) {
      // Send a confirmation to the sender if sendResponse == true
      socket.emit('send_message_response', {
        'result': 'ok',
        'status': 'online',
        'usernameFrom': usernameFrom,
        'groupID': groupID,
        'groupName': groupName,
        'usernameTo': usernameTo,
        'date': date,
        'message': message
      });
    }
  }
  else {
    // If the receiver is not logged in, save the message in DB
    this.addMessage(usernameFrom, groupID, groupName, usernameTo, date, message);
    this.save(function(err, user) {
      if (sendResponse) {
        if (err) {
          // Send an error to the sender on database error
          socket.emit('send_message_response', {
            'result': 'ko',
            'usernameFrom': usernameFrom,
            'groupID': groupID,
            'groupName': groupName,
            'username': usernameTo,
            'message': message,
            'date': date,
            'error': 'cannot save to db'
          });
        }
        else {
          // Send a confirmation to the sender if sendResponse == true
          socket.emit('send_message_response', {
            'result': 'ok',
            'status': 'offline',
            'usernameFrom': usernameFrom,
            'groupID': groupID,
            'groupName': groupName,
            'usernameTo': usernameTo,
            'date': date,
            'message': message
          });
        }
      }
    });
  }
}

// Create the user model from the user schema
var User = mongoose.model('User', UserSchema);

/*
** Mongoose schema for a group
*/
var GroupSchema = mongoose.Schema({
  name: String,
  users: Array
});

/*
** Check if a user is in the group
** Params:
**   - username: The username to check
** Returns: true or false
*/
GroupSchema.methods.userInGroup = function(username) {
  return (this.users.indexOf(username) > -1);
}

/*
** Add a user to the group
** Params:
**   - username: The username to add
*/
GroupSchema.methods.addUser = function(username) {
  if (!this.userInGroup(username))
    this.users.push(username);
}

/*
** Remove a user from a group
** Params:
**   - username: The username to remove
*/
GroupSchema.methods.removeUser = function(username) {
  var index = this.users.indexOf(username);
  if (index !== -1) {
    this.users.splice(index, 1);
  }
}

// Create the group model from the group schema
var Group = mongoose.model('Group', GroupSchema);
// Generate a unique ID token for each group
GroupSchema.plugin(mongooseIdToken)
