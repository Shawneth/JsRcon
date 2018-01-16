module.exports = {
	ontext: onTextMessage
};

var options = {
	//Used to authenticate.
	password: "deathly",
	port: 10666,
	host: "localhost"
};

var socketObject = require('./rcon.js').connectServer(options);

function onTextMessage(message){
	var commandSplit = message.split(' ');
	switch(commandSplit[0]){
		case "say":
			var text = message.slice(message.indexOf(' ') + 1);
			console.log(text);
			socketObject.sendCommand(text);
			break;
		default:
			break;
	}
}