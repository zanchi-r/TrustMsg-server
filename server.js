var app = require('express')();
var http = require('http').Server(app);
var io = require('socket.io')(http);
var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/trustmsg');
var db = mongoose.connection;
var crypto = require('crypto');
var keypair = require('keypair');

var loggedUsers = {};

function disconnect() {
    console.log('user disconnected');
}

function generatePasswordHash(password) {
    return (crypto.createHash('sha256').update(password).digest('hex'));
}

function generateRSAKeypair() {
    return (keypair({'bits': '512'}));
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
		var keys = generateRSAKeypair();
		console.log(keys['public']);
		var user = new User({'username': username, 'password': generatePasswordHash(password), 'public_key': keys['public']});
		user.save(function(err, user) {
		    if (err) {
			socket.emit('create_account_response', {
			    'result': 'ko',
			    'error': 'cannot save to db'
			});
		    }
		    else {
			socket.emit('create_account_response', {
			    'result': 'ok',
			    'key': keys['private']
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

io.on('connection', function(socket){
    console.log('a user connected');

    socket.on('create_account', function(data) {
	createAccount(data.username, data.password, socket);
    });

    socket.on('login', function(data) {
	loginUser(data.username, data.password, socket);
    });

    socket.on('disconnect', function(){
	disconnect();
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
    public_key: String
});

UserSchema.methods.isLogged = function() {
    return (this.username in loggedUsers);
}

var User = mongoose.model('User', UserSchema);
