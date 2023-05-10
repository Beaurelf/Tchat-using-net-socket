// Create a server socket and listen on port 3636
const socketio = require('socket.io');
const io = socketio.listen(3636);

let users = {};
//Creer un groupe de clients
//Example du format: {name: 'group1', membres: {client1: socket1, client2;socket2}}
let publicGroups = {};
let privateGroups = {};

let userban={};

let GroupMsgs={};
let groupEvent={};
let i=0;

// Handle event 'send' from client
io.on('connection', function(socket) {
    socket.on('send', function(data) {
        if (!data.sender || (users[data.sender] === undefined && data.action !== 'connection')) {
            handleDisconnectedUser(socket, data);
            return;
        }
        switch (data.action) {
            case 'connection':/*done*/
                handleConnectionAction(socket, data);
                break;
            case 'broadcast':/*done*/
                handleBroadcastAction(socket, data);
                break;
            case 'sendTo':/*done*/
                handleSendToAction(socket, data);
                break;
            case 'list':/*done*/
                handleListAction(socket);
                break;
            case 'quit':/*done*/
                handleQuitAction(socket, data);
                break;
            case 'cgroup':/*done*/
                handleCgroupAction(socket, data);
                break; 
            case 'join':/*done*/
                handleJgroupAction(socket, data);
                break; 
            case 'bgroup':/*done*/
                handleBgroupAction(socket, data);
                break;
            case 'members'/*done*/:
                handleGroupMembersAction(socket, data);
                break;
            case 'groups':/*done*/
                handleGroupsListAction(socket);
                break;
            case 'leave':/*done*/
                handleGroupLeaveAction(socket, data);
                break;  
            case 'invite':/*done*/
                handleGroupInviteAction(socket, data);
                break; 
            case 'msgs':/*done*/
                handleMsgsGroupAction(socket, data);
                break; 
            case 'kick':/*done*/
                handleGroupKickAction(socket, data);
                break; 
            case 'ban'/*done*/:
                handleGroupBanAction(socket, data);
                break; 
            case 'unban':/*done*/
                handleGroupUnBanAction(socket, data);
                break; 
            case 'states':
                handleGroupStatesAction(socket, data);
                break; 
            default:
                handleNotSupportedAction(socket, data)
                break;
        }
    });

    // Handle event disconnect by program
    socket.on('disconnect', function() {
        disconnectUser(socket);
    });
});

function handleDisconnectedUser(socket, data)/*done*/ {
    socket.emit('message', { sender: 'server', msg: `Sender ${data.sender} is not existed or disconnected`, event: 'error.user.notConnected' });
    socket.disconnect();
}

function handleNotSupportedAction(socket, data)/*done*/ {
    socket.emit('message', { sender: 'server', msg: `Action ${data.action} is not supported`, event: 'error.action.notSupported' });
}

function handleConnectionAction(socket, data)/*done*/ {
    let username = data.sender;
    if (users[username] !== undefined) {
        socket.emit('message', { sender: 'server', msg: `Connection failed, ${data.sender} has already been taken `, event: 'user.connectionFailed' });
        socket.disconnect();
    } else {
        users[data.sender] = socket;
        socket.emit('message', { sender: 'server', msg: `Hello ${data.sender}`, event: 'user.connected' });
        sendBroadcastMessage(socket, {
            sender: 'server',
            msg : `${data.sender} is connected`,
            user: data.sender,
            event: 'user.new'
        });
    }
}

function handleBroadcastAction(socket, data)/*done*/ {
    sendBroadcastMessage(socket, { sender: data.sender, msg: data.msg, event: 'user.broadcast' })
}
function handleSendToAction(socket, data)/*done*/ {
   
    if (users[data.receiver] == undefined) {
        socket.emit('message', { sender: 'server', msg: `An error occurs, the user ${data.receiver} is not connected `, event: 'user.SendError' });
    
    } else {
        socket= users[data.receiver] ;
        socket.emit('message', { sender: data.sender, msg: data.msg, event: 'user.send' });
    }
}

function handleListAction(socket)/*done*/ {
    socket.emit('message', { sender: 'server', users: Object.keys(users), event: 'user.list' });
}

function handleQuitAction(socket)/*done*/ {
    socket.disconnect();
}

function disconnectUser(socket)/*done*/ {
    let disconnectedUser = null;
    for (let user in users) {
        let socketId = users[user];
        if (socketId === socket) {
            disconnectedUser = user;
            break;
        }
    }
    if (disconnectedUser) {
        delete users[disconnectedUser];
        sendBroadcastMessage(socket, { sender: 'server', user: disconnectedUser, event: 'user.quit' });
    }
}

function handleCgroupAction(socket,data) /*done*/{
    
    if (data.groupType=='public'){
        if (publicGroups[data.group] !== undefined) {
            socket.emit('message', { sender: 'server', msg: `The group ${data.group} can not been created choose another group's name `, event: 'user.cgroupFailed' });
        } 
        else {
            let members = []; let messages = []; let kick = []; let ban = []; let events =[];

            members.push(data.sender)
            publicGroups[data.group] = {  group_members: members,
                group_messages : messages,
                kick_members : kick,
                ban_members : ban,
                group_events : events,
                    }
                handleSuccessfulOperation(socket,data)          
        }
    }else if(data.groupType=='private'){
        if (privateGroups[data.group] !== undefined) {
            socket.emit('message', { sender: 'server', msg: `The group ${data.group} can not been created choose another group's name `, event: 'user.cgroupFailed' });
        } else {
            let members = []; let messages = []; let kick = []; let ban = []; let events =[];

            members.push(data.sender)
            privateGroups[data.group] = {  group_members: members,
                group_messages : messages,
                kick_members : kick,
                ban_members : ban,
                group_events : events,
                    }
            handleSuccessfulOperation(socket,data)
          
        }
    }else{
        socket.emit('message', { sender: 'server', msg: `invalid command, Please specify 'private' or public' for the type of the group `, event: 'user.cgroupFailed' });
 
    }
    
}

function handleJgroupAction(socket,data) /*done*/{
    let groupName = publicGroups[data.group];
    if (groupName == undefined && privateGroups[data.group] == undefined) {
        socket.emit('message', { sender: 'server', msg: `join group failed, the group ${data.group} does not exist  `, event: 'user.jgroupFailed' });
    } else {
        if(groupName !== undefined){
        
            if(groupName.group_members.indexOf(data.sender)!==-1){
                socket.emit('message', { sender: 'server', msg: `join group failed, you are already a member of the ${data.group}  `, event: 'user.jgroupFailed' });

            }else{
                if(groupName.ban_members.indexOf(data.sender)!==-1){
                    socket.emit('message', { sender: 'server', msg: `join group failed, you have been banished from the ${data.group}  `, event: 'user.jgroupFailed' });
                }
                else{
                    groupName.group_members.push(data.sender)
                    groupName.group_events.push(`${data.sender} joined the group`)
                    console.log(groupName.group_members);
            socket.emit('message', { sender: 'server', msg: `you have been successfully added to the group`, event: 'user.jgroup' });
        sendBroadcastGroup(socket, {
                group:data.group,
                sender: data.sender,
                msg:`${data.sender} have joined the group  `,
                event: 'joinFeedback'
            },"public");
        }
        }
    }else{
        socket.emit('message', { sender: 'server', msg: `invalid operation, you are not allowed to join the ${data.group}.You have to get an invitation`, event: 'user.jgroupFailed' });

    }
}
}

function handleGroupInviteAction(socket,data)/*done*/ {
    if(users[data.dest] == undefined){
        socket.emit('message', { sender: 'server', msg: `Invalid operation, the user ${data.dest} does not exist  `, event: 'user.send' });

    }else{
        
        if (publicGroups[data.group] == undefined && privateGroups[data.group] == undefined) {
            socket.emit('message', { sender: 'server', msg: `Invalid operation, the group ${data.group} does not exist  `, event: 'user.send' });
        } 
        if (publicGroups[data.group].group_members.indexOf(data.sender)!==-1) { 
            if(publicGroups[data.group].group_members.indexOf(data.dest)==-1){    
                publicGroups[data.group].group_members.push(data.dest)
                handleSuccessfulOperation(socket,data)
                sendBroadcastGroup(socket, { sender: data.sender,
                                             group: data.group, 
                                             msg:`${data.dest} has been invited to the group ${data.group}`,
                                             event: 'user.jgroup' },"public");}
            else{
                socket.emit('message', { sender: 'server', msg: `Invalid Operation, ${data.dest} is already a member of the ${data.group}  `, event: 'user.send' });

            }
        }else if(privateGroups[data.group].group_members.indexOf(data.sender)!==-1) {
            if(privateGroups[data.group].group_members.indexOf(data.sender)==-1){    
                privateGroups[data.group].group_members.push(data.dest)
                handleSuccessfulOperation(socket,data)
                sendBroadcastGroup(socket, { sender: data.sender, 
                                            group: data.group, 
                                            msg:`${data.dest} has been invited to the group ${data.group}`, 
                                            event: 'user.jgroup' },"private");}
            else{
                socket.emit('message', { sender: 'server', msg: `Invalid Operation, ${data.dest} is already a member of the ${data.group}  `, event: 'user.send' });

            }
        }
        else{  socket.emit('message', { 
            sender: 'server', msg: 'Invalid operation, You are not allow to invite someone in this group' , event: 'user.send' });
        }
    }
       
}

function handleBgroupAction(socket,data)/*done*/ {
    if (privateGroups[data.group]!== undefined) {
        
        
        if(privateGroups[data.group].group_members.indexOf(data.sender)==-1){
            socket.emit('message', { sender: 'server', msg: `invalid operation, you are not a member of the group ${data.group} `, event: 'user.send' });

        }else{

        sendBroadcastGroup( socket,{
            sender: data.sender,
            group: data.group,
            msg: data.msg,
            event: 'user.bgroup'
        },"private");
        //adding message in the group's messages         
        privateGroups[data.group].group_messages.push(`${data.sender}>${data.msg}`);

    }
    } else if(publicGroups[data.group] !== undefined) {
        
        if(publicGroups[data.group].group_members.indexOf(data.sender)==-1){
            socket.emit('message', { sender: 'server', msg: `invalid operation, you are not a member of the group ${data.group} `, event: 'user.send' });

        }
        else{

            sendBroadcastGroup( socket,{
                sender: data.sender,
                group: data.group,
                msg: data.msg,
                event: 'user.bgroup'
            },"public");
            //adding message in the group's messages     
            publicGroups[data.group].group_messages.push(`${data.sender}>${data.msg}`);

        }
    }
    else {
        socket.emit('message', { sender: 'server', msg: `invalid operation, the group ${data.group} does not exist  `, event: 'user.send' });

    }
}

function handleGroupMembersAction(socket, data)/*done*/ {

    if(publicGroups[data.group]!==undefined){
        if(publicGroups[data.group].group_members.indexOf(data.sender)==-1){
            socket.emit('message', { sender: 'server', msg: 'invalid operation, You are not a member of this group' , event: 'user.send' });
        } else {
            socket.emit('message', {sender: 'server',group:data.group, members: publicGroups[data.group].group_members, event: 'group.members'})

        }
    }else if(privateGroups[data.group]!==undefined){
        if(privateGroups[data.group].group_members.indexOf(data.sender)==-1){
            socket.emit('message', { sender: 'server', msg: 'invalid operation, You are not a member of this group' , event: 'user.send' });
        } else {
            socket.emit('message', {sender: 'server',group:data.group, members: privateGroups[data.group].group_members, event: 'group.members'})

        }
    }else {
        socket.emit('message', { sender: 'server', msg: `Msgs group failed, the group ${data.group} does not exist  `, event: 'user.send' });

    }
}

function handleMsgsGroupAction(socket, data)/*done*/ {

    if(publicGroups[data.group]!==undefined){
        if(publicGroups[data.group].group_members.indexOf(data.sender)==-1){
            socket.emit('message', { sender: 'server', msg: 'invalid operation, You are not a member of this group' , event: 'user.send' });
        } else {
            socket.emit('message', {sender: 'server',group:data.group, messages: publicGroups[data.group].group_messages, event: 'group.messages'})

        }
    }else if(privateGroups[data.group]!==undefined){
        if(privateGroups[data.group].group_members.indexOf(data.sender)==-1){
            socket.emit('message', { sender: 'server', msg: 'invalid operation, You are not a member of this group' , event: 'user.send' });
        } else {
            socket.emit('message', {sender: 'server',group:data.group, messages: privateGroups[data.group].group_messages, event: 'group.messages'})

        }
    }else {
        socket.emit('message', { sender: 'server', msg: `Msgs group failed, the group ${data.group} does not exist  `, event: 'user.send' });

    }
}

function handleGroupStatesAction(socket, data) {
    if(publicGroups[data.group]!==undefined){
        if(publicGroups[data.group].group_members.indexOf(data.sender)==-1){
            socket.emit('message', { sender: 'server', msg: 'invalid operation, You are not a member of this group' , event: 'user.send' });
        } else {
            socket.emit('message', {sender: 'server',group:data.group, states: publicGroups[data.group].group_events, event: 'group.states'})

        }
    }else if(privateGroups[data.group]!==undefined){
        if(privateGroups[data.group].group_members.indexOf(data.sender)==-1){
            socket.emit('message', { sender: 'server', msg: 'invalid operation, You are not a member of this group' , event: 'user.send' });
        } else {
            socket.emit('message', {sender: 'server',group:data.group, states: privateGroups[data.group].group_events, event: 'group.states'})

        }
    }else {
        socket.emit('message', { sender: 'server', msg: `Msgs group failed, the group ${data.group} does not exist  `, event: 'user.send' });

    }

}
//we are not able to see the list of private groups
function handleGroupsListAction(socket)/*done*/ {
    socket.emit('message', {sender: 'server', groups: Object.keys(publicGroups), event: 'group.list'})
}

function handleGroupLeaveAction(socket, data) /*done*/{
    if(publicGroups[data.group]==undefined && privateGroups[data.group]==undefined) {
        socket.emit('message', { sender: 'server', msg: 'invalid operation, the group does not exist' , event: 'user.send' });
        return;
    }
    if(publicGroups[data.group].group_members.indexOf(data.sender)!==-1){
                
                ind = publicGroups[data.group].group_members.indexOf(data.sender)
                publicGroups[data.group].group_members.splice(ind,1)
                sendBroadcastGroup(socket, { sender: data.sender, group: data.group, event: 'group.leave' },"public");
                handleSuccessfulOperation(socket,data)
                    
    } else if(privateGroups[data.group].group_members.indexOf(data.sender)!==-1){
                
            ind = privateGroups[data.group].group_members.indexOf(data.sender)
            privateGroups[data.group].group_members.splice(ind,1)
            sendBroadcastGroup(socket, { sender: data.sender, group: data.group, event: 'group.leave' },"private");
            handleSuccessfulOperation(socket,data)
    }
    else{
            socket.emit('message', { sender: 'server', msg: 'invalid operation, You are not a member of this group' , event: 'user.send' });
    }
}

function handleGroupKickAction(socket, data)/*done*/ {

    if(users[data.dest] == undefined){
        socket.emit('message', { sender: 'server', msg: `Invalid operation, the user ${data.dest} does not exist  `, event: 'user.send' });

    }else{
        
        if (publicGroups[data.group] == undefined && privateGroups[data.group] == undefined) {
            socket.emit('message', { sender: 'server', msg: `Invalid operation, the group ${data.group} does not exist  `, event: 'user.send' });
        } 
        if (publicGroups[data.group].group_members.indexOf(data.sender)!==-1) { 

            if(publicGroups[data.group].group_members.indexOf(data.dest)!==-1){   

                ind = publicGroups[data.group].group_members.indexOf(data.dest)
                publicGroups[data.group].group_members.splice(ind,1)
                sendBroadcastGroup(socket, { sender: data.sender,
                                             group: data.group,
                                             msg:`kicked ${data.dest}`,
                                             reason : data.reason,
                                             event: 'group.kick' },"public");
                handleSuccessfulOperation(socket,data)
                //adding an event in groups_events
                publicGroups[data.group].group_events.push(`${data.sender} kicked ${data.dest}`)
            }
            else{
                socket.emit('message', { sender: 'server', msg: `Invalid Operation, ${data.dest} is not a member of the ${data.group}  `, event: 'user.send' });

            }
        }else if(privateGroups[data.group].group_members.indexOf(data.sender)!==-1) {
            if(privateGroups[data.group].group_members.indexOf(data.dest)!==-1){    
                ind = privateGroups[data.group].group_members.indexOf(data.dest)
                privateGroups[data.group].group_members.splice(ind,1)
                sendBroadcastGroup(socket, { sender: data.sender,
                                             group: data.group,
                                             msg:`kicked ${data.dest}`,
                                             reason : data.reason,
                                             event: 'group.kick' },"private");
                handleSuccessfulOperation(socket,data)
                //adding an event in groups_events
                privateGroups[data.group].group_events.push(`${data.sender} kicked ${data.dest}`)
            }
            else{
                socket.emit('message', { sender: 'server', msg: `Invalid Operation, ${data.dest} is not a member of the ${data.group}  `, event: 'user.send' });

            }
        }
        else{  socket.emit('message', { 
            sender: 'server', msg: 'Invalid operation, You are not allow to kick someone in this group' , event: 'user.send' });
        }
    }
}
function handleGroupBanAction(socket, data) {
    if (publicGroups[data.group] == undefined && privateGroups[data.group] == undefined ) {
        socket.emit('message', { sender: 'server', msg: `Invalid operation, the group ${data.group} does not exist  `, event: 'user.send' });
    } 
    if(users[data.dest] == undefined){
        socket.emit('message', { sender: 'server', msg: `Invalid operation, the user ${data.dest} does not exist  `, event: 'user.send' });

    }else{
        
        if (publicGroups[data.group] == undefined && privateGroups[data.group] == undefined) {
            socket.emit('message', { sender: 'server', msg: `Invalid operation, the group ${data.group} does not exist  `, event: 'user.send' });
        } 
        if (publicGroups[data.group].group_members.indexOf(data.sender)!==-1) { 

            if(publicGroups[data.group].group_members.indexOf(data.dest)!==-1){   

                ind = publicGroups[data.group].group_members.indexOf(data.dest)
                publicGroups[data.group].group_members.splice(ind,1)
                publicGroups[data.group].ban_members.push(data.dest)
                sendBroadcastGroup(socket, { sender: data.sender,
                                             group: data.group,
                                             msg:`banished ${data.dest}`,
                                             reason : data.reason,
                                             event: 'group.kick' },"public");
                handleSuccessfulOperation(socket,data)
                //adding an event in groups_events
                publicGroups[data.group].group_events.push(`${data.sender} banished ${data.dest}`)
            }
            else{
                socket.emit('message', { sender: 'server', msg: `Invalid Operation, ${data.dest} is not a member of the ${data.group}  `, event: 'user.send' });

            }
        }else if(privateGroups[data.group].group_members.indexOf(data.sender)!==-1) {
            if(privateGroups[data.group].group_members.indexOf(data.dest)!==-1){    
                ind = privateGroups[data.group].group_members.indexOf(data.dest)
                privateGroups[data.group].group_members.splice(ind,1)
                publicGroups[data.group].ban_members.push(data.dest)
                sendBroadcastGroup(socket, { sender: data.sender,
                                             group: data.group,
                                             msg:`banished ${data.dest}`,
                                             reason : data.reason,
                                             event: 'group.kick' },"private");
                handleSuccessfulOperation(socket,data)
                //adding an event in groups_events
                privateGroups[data.group].group_events.push(`${data.sender} banished ${data.dest}`)
            }
            else{
                socket.emit('message', { sender: 'server', msg: `Invalid Operation, ${data.dest} is not a member of the ${data.group}  `, event: 'user.send' });

            }
        }
        else{  socket.emit('message', { 
            sender: 'server', msg: 'Invalid operation, You are not banish to invite someone in this group' , event: 'user.send' });
        }
    }
}

function handleGroupUnBanAction(socket, data) {
    if (publicGroups[data.group] == undefined && privateGroups[data.group] == undefined ) {
        socket.emit('message', { sender: 'server', msg: `Invalid operation, the group ${data.group} does not exist  `, event: 'user.send' });
    } 
    if(users[data.dest] == undefined){
        socket.emit('message', { sender: 'server', msg: `Invalid operation, the user ${data.dest} does not exist  `, event: 'user.send' });

    }else{
        
        if (publicGroups[data.group] == undefined && privateGroups[data.group] == undefined) {
            socket.emit('message', { sender: 'server', msg: `Invalid operation, the group ${data.group} does not exist  `, event: 'user.send' });
        } 
        if (publicGroups[data.group].group_members.indexOf(data.sender)!==-1) { 

            if(publicGroups[data.group].ban_members.indexOf(data.dest)!==-1){   

                ind = publicGroups[data.group].ban_members.indexOf(data.dest)
                publicGroups[data.group].ban_members.splice(ind,1)
                sendBroadcastGroup(socket, { sender: data.sender,
                                             group: data.group,
                                             msg:`unbanished ${data.dest}`,
                                             event: 'group.unban' },"public");
                handleSuccessfulOperation(socket,data)
                //adding an event in groups_events
                publicGroups[data.group].group_events.push(`${data.sender} unbanished ${data.dest}`)

            }
            else{
                socket.emit('message', { sender: 'server', msg: `Invalid Operation, ${data.dest} is not a member of the ${data.group}  `, event: 'user.send' });

            }
        }else if(privateGroups[data.group].group_members.indexOf(data.sender)!==-1) {
            if(privateGroups[data.group].ban_members.indexOf(data.dest)!==-1){   

                ind = privateGroups[data.group].ban_members.indexOf(data.dest)
                privateGroups[data.group].ban_members.splice(ind,1)
                sendBroadcastGroup(socket, { sender: data.sender,
                                             group: data.group,
                                             msg:`unbanished ${data.dest}`,
                                             event: 'group.unban' },"public");
                handleSuccessfulOperation(socket,data)
                //adding an event in groups_events
                privateGroups[data.group].group_events.push(`${data.sender} unbanished ${data.dest}`)

            }
            else{
                socket.emit('message', { sender: 'server', msg: `Invalid Operation, ${data.dest} is not a member of the ${data.group}  `, event: 'user.send' });

            }
        }
        else{  socket.emit('message', { 
            sender: 'server', msg: 'Invalid operation, You are not banish to invite someone in this group' , event: 'user.send' });
        }
    }
}


function sendBroadcastMessage(socket, data)/*done*/ {
    socket.broadcast.emit('message', data);
}
function sendBroadcastGroup(socket,data,state)/*done*/ {
    T = Object.keys(users)
    if (state="public"){   
       
        console.log(publicGroups[data.group].group_members)
        for(let i = 0;i<T.length;i++){
            if (users[T[i]]!=socket && publicGroups[data.group].group_members.indexOf(T[i])!=-1)
        { users[T[i]].emit('message', data); console.log("oui")}
        }
    }
    else{
        T = Object.keys(users)
        console.log(privateGroups[data.group].group_members)
        for(let i = 0;i<T.length;i++){
            if (users[T[i]]!=socket && privateGroups[data.group].group_members.indexOf(T[i])!=-1)
        { users[T[i]].emit('message', data); console.log("oui")}
        }
    }
    
}
function  handleSuccessfulOperation(socket,data)/*done*/{
    socket.emit('message', { sender: 'server', msg: `The operation occurs succesfully`, event: 'successOperation' });

}

    

