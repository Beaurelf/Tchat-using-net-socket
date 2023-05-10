// Create a client socket and connect to port 3636
const socketio = require('socket.io-client');
const socket = socketio.connect("http://localhost:3636");

// Read user's input
const readline = require('readline');
const { Console } = require('console');
const rl = readline.createInterface(process.stdin, process.stdout);

// Variable to keep user's nickname
let nickname = '';
let isConnected = false;

// Process user's input
rl.on('line', function(line) {
    if (!isConnected) {
        console.log("You have been disconnected. Please close the program and reconnect");
        return;
    }
    if (line.match(/^b;.+$/)) {
        socket.emit('send', { sender: nickname, msg: getUserInputMessage(line)[1], action: 'broadcast' });
    } else if (line.match(/^ls;$/)) {
        socket.emit('send', { sender: nickname, action: 'list' });
    } else if (line.match(/^q;/)) {
        isConnected = false;
        socket.emit('send', { sender: nickname, action: 'quit' })
    }else if(line.match(/^s;.+;.+$/)){
        socket.emit('send', { sender: nickname, to: getUserInputMessage(line)[1],msg:getUserInputMessage(line)[2], action: 'sendTo' });
    }else if(line.match(/^cg;.+$/)){
        socket.emit('send', { sender: nickname, group: getUserInputMessage(line)[1], groupType:getUserInputMessage(line)[2], action: 'cgroup' });
    }else if(line.match(/^j;.+$/)){
        socket.emit('send', { sender: nickname, group: getUserInputMessage(line)[1], action: 'join' });
    }else if(line.match(/^bg;.+$/)){
        socket.emit('send', { sender: nickname, group: getUserInputMessage(line)[1], msg:getUserInputMessage(line)[2], action: 'bgroup' });
    }else if (line.match(/^members;.+$/)){
        socket.emit('send', {sender: nickname, group: getUserInputMessage(line)[1], action:'members'})
    } else if (line.match(/^groups;$/)){
        socket.emit('send', {sender: nickname, action:'groups'})
    } else if (line.match(/^leave;.+$/)){
        socket.emit('send', {sender: nickname, group: getUserInputMessage(line)[1], action:'leave'})
    } else if (line.match(/^kick;.+$/)){
        socket.emit('send', {sender: nickname, group: getUserInputMessage(line)[1], dest:getUserInputMessage(line)[2], reason: getUserInputMessage(line)[3],action:'kick'})
    }else if (line.match(/^ban;.+$/)){
        socket.emit('send', {sender: nickname, group: getUserInputMessage(line)[1], dest:getUserInputMessage(line)[2], reason: getUserInputMessage(line)[3],action:'ban'})
    }else if (line.match(/^unban;.+;.+$/)){
        socket.emit('send', {sender: nickname, group: getUserInputMessage(line)[1], dest:getUserInputMessage(line)[2],action:'unban'})
    }else if (line.match(/^messages;.+$/)){
        socket.emit('send', {sender: nickname, group: getUserInputMessage(line)[1],action:'msgs'})
    }else if (line.match(/^states;.+$/)){
    socket.emit('send', {sender: nickname, group: getUserInputMessage(line)[1],action:'states'})
    }else if (line.match(/^invite;.+$/)){
        socket.emit('send', {sender: nickname, group: getUserInputMessage(line)[1], dest:getUserInputMessage(line)[2],action:'invite'})
    }

    rl.prompt(true);
});

function getUserInputMessage(line) {
    let inputs = []
    inputs = line.split(';')
    return inputs;
}



// Handle events from server
socket.on('message', function(data) {
    switch (data.event) {
        case 'user.connected': /*done*/
            handleConnectedEvent(data);
            break;
        case 'user.connectionFailed':/*done*/
            handleConnectionFailedEvent(data);
            break;
        case 'user.new':/*done*/
            handleFowardingEvent(data);
            break;
        case 'user.list':/*done*/
            handleListEvent(data);
            break;
        case 'user.quit':/*done*/
            handleQuitEvent(data);
            break;
        case 'user.broadcast':/*done*/
            handleFowardingEvent(data);
            break;
        case 'user.send':/*done*/
            handleFowardingEvent(data); // using the broadcast handle function as Send handle function instead of creating a new similar function
            break;
        case 'successOperation':/*done*/
            handleFowardingEvent(data);// using handleFowardingEvent instead of having a new function handleSuccessOperationEvent
            break;
        case 'joinFeedback':/*done*/
            handleFowardingEvent(data); // using handleFowardingEvent instead of having a new function handleJoinFeedbackEvent
            break;
        case 'user.jgroup':/*done*/
            handleGroupJoinEvent(data);
            break;
        case 'user.bgroup':/*done*/
            handleGroupBroadcastEvent(data);
            break;
        case 'group.members':/*done*/
            handleGroupMembersEvent(data);
            break;
        case 'group.msgs':/*done*/
            handleGroupMessagesEvent(data);
            break;
        case 'group.list'/*done*/:
            handleGroupsListEvent(data);
            break;
        case 'group.leave'/*done*/:
            handleUserLeaveEvent(data);
            break;
        case 'group.kick':/*done*/
            handleGroupKickEvent(data);
            break;
        /*case 'ban':
            handleBanEvent(data);
            break;*/
        case 'group.unban':
            handleGroupUnBanEvent(data);
            break;
        
        case 'group.states':
            handleGroupStatesEvent(data);
            break; 

        default:
            handleUnknownEvent(data);
            break;
    }
    rl.prompt(true);
});

function handleUnknownEvent(data)/*done*/ {
    console.log(data.msg);
}

function handleConnectedEvent(data)/*done*/ {
    isConnected = true;
    console.log(data.msg);
}

function handleConnectionFailedEvent(data)/*done*/ {
    isConnected = false;
    console.log(data.msg);
}

function handleListEvent(data)/*done*/ {
    for (let user of data.users) {
        console.log(`${user}`)
    }
}

function handleQuitEvent(data)/*done*/ {
    console.log(`${data.user} left the chat.`)
}

function handleFowardingEvent(data)/*done*/{
    console.log(`${data.sender}> ${data.msg}`);
}

function handleGroupJoinEvent(data)/*done*/{
    console.log(`${data.group}>${data.sender}> ${data.msg}`);
}

function handleGroupBroadcastEvent(data)/*done*/{
    console.log(`${data.group}: ${data.sender}>${data.msg}`);
}

function handleGroupMembersEvent(data)/*done*/ {
    console.log(` List of the Members of the group ${data.group}:`);

    for (var item of data.members ){
        console.log(""+item);
    }
    console.log('end List')
}
function handleGroupMessagesEvent(data)/*done*/ {
    console.log(` List of the messages of the group ${data.group}:`);

    for (var item of data.messages ){
        console.log(""+item);
    }
    console.log('end List')
}
function handleGroupStatesEvent(data) {
    console.log(`List of the events occured in the group ${data.group}:`);

    for (var item of data.states ){
        console.log("---> "+item);
    }
    console.log('end List')
}

function handleGroupsListEvent(data)/*done*/ {
    console.log(` List of the public groups :`);

    for (var item of data.groups ){
        console.log(""+item);
    }
    console.log('end List')
}
function handleGroupKickEvent(data){
    console.log(`${data.group}: ${data.sender} ${data.msg} ${data.sender} `);
}
/*function handleBanEvent(data){
    console.log(`group ${data.group}: ${data.msg}`);
}*/
function handleGroupUnBanEvent(data){
    console.log(`${data.msg}`);
}

function handleUserLeaveEvent(data)/*done*/{
    console.log(`${data.group}: ${data.sender} left the group.`)
}



function main() {
    if (process.argv.length == 4 && process.argv[2] == '--name') {
        nickname = process.argv[3];
        socket.emit('send', { sender: nickname, action: 'connection' });
    } else {
        // Set the username
        rl.question('Please enter a name: ', function(nameInput) {
            nickname = nameInput;
            socket.emit('send', { sender: nickname, action: 'connection' });
            rl.prompt(true);
        });
    }
}

main();