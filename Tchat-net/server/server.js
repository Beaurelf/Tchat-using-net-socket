
var net = require('net');
var PORT = '';
var HOST = '';
var yargs = require('yargs');
const db = require('./../dataBase/dataBase')
const aes256 = require('aes256');
const Bcrypt = require('bcryptjs')
const Crypto = require('crypto')

const ServerKey = Crypto.createECDH('secp256k1');
ServerKey.generateKeys()

const ServerPublicKeyBase64 = ServerKey.getPublicKey().toString('base64');
var ServerSharedKey = null


if (yargs.argv.PORT != undefined && yargs.argv.HOST != undefined) {
    PORT = yargs.argv.PORT;
    HOST = yargs.argv.HOST;
}else{
    if (yargs.argv.PORT != undefined) {
        PORT = yargs.argv.PORT;
        HOST = '127.0.0.1';
    }else{
        if (yargs.argv.HOST != undefined) {
            PORT = '8080';
            HOST = yargs.argv.HOST;
        }else{
            PORT = '8080';
            HOST = '127.0.0.1';
        }
    }
}

console.log("SERVER START PORT:"+ PORT +" AND HOST:" +HOST);

var clients = []
var groups = []

var server = net.createServer((socket)=>{

    console.log('CONNECTED from ' + socket.remoteAddress + ':' + socket.remotePort);
    init()
    socket.on('data', function(data) {
            msg = JSON.parse(data);
            console.log('DATA received from ' + socket.remoteAddress + ':' + data);
            switch(msg.action){
                case'client-key':
                ServerSharedKey = ServerKey.computeSecret(msg.data, 'base64', 'hex');
                socket.write(JSON.stringify({'data':ServerPublicKeyBase64,'action':'server-key'}))
                    break;
                case'client-hello': 
                    if(msg.login){
                        clients.push({'id': socket.remotePort, 'name' : msg.from, 'socket' : socket});
                        if(db.findUserNameByName(msg.from).length > 0){
                            console.log(comparePassword(aes256.decrypt(ServerSharedKey,msg.pwd), db.getPasswordUserByName(msg.from)))
                            if(comparePassword(aes256.decrypt(ServerSharedKey,msg.pwd), db.getPasswordUserByName(msg.from))){
                                let message = []
                                db.getUserMsgReceived(msg.from).map(m=>{
                                    if(m.Id_group == ''){
                                        message.push({'from':db.findUserNameById(m.Id_user),
                                        'content':m.content, 'group':''})
                                    }else{
                                        message.push({'from':db.findUserNameById(m.Id_user),
                                        'content':m.content, 'group':db.findNameGroupById(m.Id_group).group_name})
                                    }
                                })
                                socket.write(JSON.stringify({"sender-ip":socket.remoteAddress+':'+socket.remotePort,"action":"server-hello","msg":"Hello" + ' '+ msg.from,
                                'data':message}));
                                db.updateStatus(msg.from,'ONLINE')
                            }else{
                                socket.write(JSON.stringify({"sender-ip":socket.remoteAddress+':'+socket.remotePort,"action":"server-hello","msg":"Username or password is incorrect"}));
                                leaveServer(msg.from)
                            }
                        }else{
                            socket.write(JSON.stringify({"sender-ip":socket.remoteAddress+':'+socket.remotePort,"action":"server-hello","msg":"Username or password is incorrect"}));
                            leaveServer(msg.from)
                        }
                    }else{
                        clients.push({'id': socket.remotePort, 'name' : msg.from, 'socket' : socket});
                        socket.write(JSON.stringify({"sender-ip":socket.remoteAddress+':'+socket.remotePort,"action":"server-hello","msg":"Hello" + ' '+ msg.from}));
                        saveUser(msg.from, aes256.decrypt(ServerSharedKey,msg.pwd))
                    }
                    break;
                case'client-send':
                    if(db.findUserNameByName(msg.to).length > 0){
                        let clientTo = searchClient(msg.to)
                    if (clientTo != null) {
                        clientTo.write(JSON.stringify({"from": msg.from,"action":"server-send","msg": aes256.decrypt(ServerSharedKey,msg.msg)}));
                    }
                    db.saveMsg(msg.from,msg.to,msg.msg,'');
                    }else{
                        socket.write(JSON.stringify({"action":"server-send-error","msg": "This user don't exist"}));
                    }
                    break;
                case'client-broadcast':
                    broadcastSending(msg.from,'Received from '+msg.from+': '+ aes256.decrypt(ServerSharedKey,msg.msg));
                    break;
                case'client-list-clients':
                    let listClient = [];
                    clients.map(c=>{
                        listClient.push(c.name)
                    })
                    socket.write(JSON.stringify({"from": msg.from,"action":"server-list-clients","data": listClient}));
                    break;
                case'client-quit':
                    leaveServer(msg.from) 
                    db.updateStatus(msg.from,'OFFLINE')          
                    break;
                case'client-error':
                    if(msg.error == 'disconnected'){
                        leaveServer(msg.from)
                    }else{
                        broadcastSending(msg.from,  msg.from + ' is connected',true)
                    }
                    break;
                case 'cgroup':
                    if(msg.type){
                        if (msg.type.toLocaleLowerCase() == 'public') {
                            groups.push({'name': msg.group, 'admin' : msg.sender , 'members':[msg.sender],
                                'msg':[], 'excluded':[], 'states':[`${msg.sender} create group ${msg.group}`],
                                'type':'public'})
                                socket.write(JSON.stringify({"action":"server-cgroup",
                                "msg":"the group was created"}))
                            db.saveGroup(msg.group,msg.type);
                            db.saveUserGroup(msg.sender, msg.group)
                            db.saveState(`${msg.sender} create group ${msg.group}`, msg.group)
                        }else{
                            if (msg.type.toLocaleLowerCase() == 'private') {
                                groups.push({'name': msg.group, 'admin' : msg.sender , 'members':[msg.sender],
                                    'msg':[], 'excluded':[], 'states':[`${msg.sender} create group ${msg.group}`],
                                    'type':'private', 'invited':[]})
                                    socket.write(JSON.stringify({"action":"server-cgroup",
                                    "msg":"the group was created"}))  
                                db.saveGroup(msg.group,msg.type);
                                db.saveUserGroup(msg.sender, msg.group)
                                db.saveState(`${msg.sender} create group ${msg.group}`,msg.group)
                            }else{
                                socket.write(JSON.stringify({"action":"server-cgroup","msg": "You must choose between public or private"}));
                            }   
                        }
                    }else{
                        groups.push({'name': msg.group, 'admin' : msg.sender , 'members':[msg.sender],
                            'msg':[], 'excluded':[], 'states':[`${msg.sender} create group ${msg.group}`],
                            'type':'public'})
                            socket.write(JSON.stringify({"action":"server-cgroup",
                            "msg":"the group was created"}))
                        db.saveGroup(msg.group,'public');
                        db.saveUserGroup(msg.sender, msg.group)
                        db.saveState(`${msg.sender} create group ${msg.group}`,msg.group)
                    }
                    break;
                case 'join':
                    let group = findGroup(msg.group)
                    if (group != null) {
                        if (group.members.includes(msg.sender ,0)) {
                            socket.write(JSON.stringify({"action":"server-jgroup-already",
                            "msg": "You are already member of this group"}));
                        }else{
                            if(group.type == 'public'){
                                if(!isExcluded(msg.group, msg.sender)){
                                    group.members.push(msg.sender)
                                    socket.write(JSON.stringify({"action":"server-jgroup",
                                    "msg": "You joined the group " + msg.group}));
                                    broadcastGroupSending(msg.sender, `${msg.sender} joined group ${msg.group}`,
                                    msg.group,true);
                                    group.states.push(`${msg.sender} join group ${msg.group}`) 
                                    db.saveUserGroup(msg.sender, msg.group)
                                    db.saveState(`${msg.sender} join group ${msg.group}`,msg.group)
                                }else{
                                    socket.write(JSON.stringify({"action":"server-jgroup",
                                    "msg": "You can't enter in this group you are bannished"}));
                                } 
                            }else{
                                if (group.invited.includes(msg.sender,0)) {
                                    group.members.push(msg.sender)
                                    socket.write(JSON.stringify({"action":"server-jgroup",
                                    "msg": "You joined the group " + msg.group}));
                                    broadcastGroupSending(msg.sender, `${msg.sender} joined group ${msg.group}`,
                                    msg.group,true);
                                    group.states.push(`${msg.sender} join group ${msg.group}`) 
                                    db.saveUserGroup(msg.sender, msg.group)
                                    db.saveState(`${msg.sender} join group ${msg.group}`,db.findIdGroupByName(msg.group))
                                }else{
                                    socket.write(JSON.stringify({"action":"server-jgroup",
                                    "msg": "You need invitation before enter in this group"}));
                                }
                            }
                        
                        } 
                    }else{
                        socket.write(JSON.stringify({"action":"server-group-not-exist",
                        "msg": "This group don't exist"}));
                    }
                    break;
                case 'gbroadcast':
                    let group2 = findGroup(msg.group)
                    if (group2 != null) {
                        if (group2.members.includes(msg.sender, 0)){
                                group2.msg.push({'from': msg.sender , 
                                'content': aes256.decrypt(ServerSharedKey,msg.msg)})
                                broadcastGroupSending(msg.sender, 'received from '
                                +msg.sender+': '+aes256.decrypt(ServerSharedKey,msg.msg), msg.group); 
                        }else{
                            socket.write(JSON.stringify({"action":"server-gbroadcast-error",
                            "msg": "This group don't exist or You are not member of this group"}));    
                        } 
                    }else{
                        socket.write(JSON.stringify({"action":"server-gbroadcast-error",
                        "msg": "This group don't exist or You are not member of this group"}));
                    }
                    break;
                case 'members':
                    if (findGroup(msg.group) != null) {
                        socket.write(JSON.stringify({"action":"server-members-group","group":msg.group, 
                        "data": findGroup(msg.group).members}));
                        break;
                    }else{
                        socket.write(JSON.stringify({"action":"server-group-not-exist",
                        "msg": "This group don't exist"}));
                    }
                    break;
                case 'groups':
                    let listGroup = []
                    groups.map(g=>{
                        listGroup.push(g.name +' :' + g.type );
                    })
                    socket.write(JSON.stringify({"from": msg.from,"action":"server-groups","data": listGroup}));
                    break;
                case 'msgs':
                    let listMsg = []
                    findGroup(msg.group).msg.map(m=>{
                        listMsg.push(m);
                    })
                    socket.write(JSON.stringify({"from": msg.from,"group":msg.group,
                    "action":"server-msgs","data": listMsg}));
                    break;
                case 'leave':
                    if (findGroup(msg.group).members.includes(msg.sender, 0)){
                        leaveGroup(msg.sender,msg.group);
                        findGroup(msg.group).states.push(`${msg.sender} leave group ${msg.group}`)
                        db.saveState(`${msg.sender} leave group ${msg.group}`,msg.group)
                    }else{
                        socket.write(JSON.stringify({"action":"server-send-error",
                        "msg": "This group don't exist or you are not member of "+msg.group}));
                    }
                    break;
                case 'invite':
                    if(searchClient(msg.dest) != null){
                        searchClient(msg.dest).write(JSON.stringify({"from": msg.sender,"action":"server-send",
                        "msg":`${msg.sender} invite you to join group ${msg.group}`}));
                        if(findGroup(msg.group).invited){
                            findGroup(msg.group).invited.push(msg.dest);
                        }
                        db.invitedGroup(msg.dest, msg.group)
                    }else{
                        socket.write(JSON.stringify({"action":"server-send-error","msg": "This user or group don't exist"}));
                    }
                    break;
                case 'kick':
                    if (findGroup(msg.group).members.includes(msg.sender, 0)){
                        kickGroup(msg.sender, msg.dest, msg.group, msg.reason,"excluded")
                        findGroup(msg.group).states.push(`${msg.sender} excluded ${msg.dest} from the group ${msg.group}`)
                        db.saveState(`${msg.sender} excluded ${msg.dest} from the group ${msg.group}`,msg.group)
                    }else{
                        socket.write(JSON.stringify({"action":"server-send-error",
                        "msg": "This group don't exist"+msg.dest+"are not member of "+msg.group}));
                    }
                    break;
                case 'ban':
                    if (findGroup(msg.group).members.includes(msg.sender, 0)){
                        findGroup(msg.group).excluded.push(msg.dest);
                        kickGroup(msg.sender, msg.dest, msg.group, msg.reason, "bannished");
                        findGroup(msg.group).states.push(`${msg.sender} banned ${msg.dest} from the group ${msg.group}`)
                        db.saveState(`${msg.sender} banned ${msg.dest} from the group ${msg.group}`,msg.group)
                        db.bannishedGroup(msg.dest, msg.group)
                    }else{
                        socket.write(JSON.stringify({"action":"server-send-error",
                        "msg": "This group don't exist"+msg.dest+"are not member of "+msg.group}));
                    }
                    break;
                case 'unban':
                    unban(msg.sender,msg.dest, msg.group)
                    findGroup(msg.group).states.push(`${msg.sender} unbanned ${msg.dest} from the group ${msg.group}`)
                    db.saveState(`${msg.sender} unbanned ${msg.dest} from the group ${msg.group}`,msg.group)
                    db.unbannishedGroup(msg.dest, msg.group)
                    break;
                case 'states':
                    let listState = []
                    findGroup(msg.group).states.map(s=>{
                        listState.push(s);
                    })
                    socket.write(JSON.stringify({"from": msg.from,"group":msg.group,
                    "action":"server-states","data": listState}));
                    break;
                case 'delete':
                    db.deleteSession(msg.sender)
                    leaveServer(msg.sender)
                default:
                    console.log(data);               
            }
        });
    }).listen(PORT, HOST);

/*** functions used ***/

/** function client **/

function init(){
    db.getAllgroup().map(g=>{
        let group = {'name': '', 'admin' : '' , 'members':[],'msg':[], 'excluded':[],
         'states':[],'type':'public'}
        group.name = g.group_name
        group.type = g.type
        db.getStateGroup(g.Id).map(s=>{
            group.states.push(s.event)
        })
        db.getListBannedGroup(g.Id).map(b=>{
            group.excluded.push(b.username)
        })
        db.getMembersGroup(g.Id).map(m=>{
            group.members.push(m.username)
        })
        db.getGroupMsg(g.Id).map(m=>{
            group.msg.push({'from': db.findUserNameById(m.Id_user) , 'content': m.content})
        })
        groups.push(group)
    })
}

function searchClient(clientName){
    let client = null
    let  k = 0
    while (k <= clients.length - 1) {
        if (clients[k].name == clientName) {
            client = clients[k].socket;
            break;
        }else{
            k++;
        }
    }
    return client;
}

function broadcastSending(sender, msg, server){
    let client = searchClient(sender)
    if(client != null){
        clients.map(c=>{
            if(c.id != client.remotePort){
                let S = c.socket;
                S.write(JSON.stringify({"from": sender,"action":"server-broadcast","msg": msg}));
            }
        })
        if (!server) {
            db.getAllUser().map(u=>{
                if(u.username != sender){
                    db.saveMsg(sender,u.username,msg.substring(msg.indexOf(':')+1),'');
                }
            })
        }
    }
}

function leaveServer(clientName){
    let client = searchClient(clientName)
    client.write(JSON.stringify({"action":"server-quit"}));
    let j = 0
    client.end();
    while (j <= clients.length - 1) {
        if (clients[j].id == client.remotePort) {
            break;
        }else{
            j++;
        }
    }
    clients.splice(j,1);
    clients.map(c=>{
        let S = c.socket;
        S.write(JSON.stringify({"from": clientName,"action":"server-broadcast",
        "msg": `Received from server : ${clientName} left chat`}));
    })    
}

/** function group **/

function findGroup(groupName){
    let group = null
    let  k = 0
    while (k <= groups.length - 1) {
        if (groups[k].name == groupName) {
            group = groups[k];
            break;
        }else{
            k++;
        }
    }
    return group;
}

function getMembersGroup(groupName){
    let members = [];
    clients.map(client=>{
        if (findGroup(groupName).members.includes(client.name, 0)){
            members.push(client);
        }
    })
    return members;
}

function broadcastGroupSending(sender, msg, groupName, server){
    let client = searchClient(sender)
    getMembersGroup(groupName).map(member=>{
        if (member.id != client.remotePort) {
            let S = member.socket;
            S.write(JSON.stringify({"from": sender,"group":groupName,
            "action":"server-gbroadcast",msg}));
        }
    })  
    if (!server) {
        db.getMembersGroup(db.findIdGroupByName(groupName)).map(m=>{
            if(m.username != sender){
                db.saveMsg(sender,m.username,msg.substring(msg.indexOf(':')+1),'');
            }
        })
    }
}

function leaveGroup(clientName, groupName){
    let j = 0
    while (j <= findGroup(groupName).members.length - 1) {
        if ( findGroup(groupName).members[j] == clientName) {
            break;
        }else{
            j++;
        }
    }
    findGroup(groupName).members.splice(j,1)
    broadcastGroupSending(clientName, `${clientName} left group ${groupName}`, groupName,true)
    db.leaveGroup(clientName, groupName)
}

function kickGroup(clientSender, clientReceiver, groupName, reason, s){
    let j = 0
    let clientKick = searchClient(clientReceiver)
    while (j <= findGroup(groupName).members.length - 1) {
        if ( findGroup(groupName).members[j] == clientReceiver) {
            break;
        }else{
            j++;
        }
    }
    findGroup(groupName).members.splice(j,1)
    if(clientKick!=null){
        clientKick.write(JSON.stringify({"from": clientSender,"group":groupName,
        "action":"server-send","msg":`You were ${s}  by ${clientSender} for ${reason}`}))
        broadcastGroupSending(clientSender, `${clientReceiver}  was  ${s}  by 
        ${clientSender} from ${groupName} for ${reason}`, groupName,true)
    }
    db.leaveGroup(clientReceiver, groupName)
}

function isExcluded(groupName, clientName){
    let  k = 0
    let b = false
    let group = findGroup(groupName)
    while (k <= group.excluded.length - 1) {
        if ( group.excluded[k] == clientName) {
            b = true
            break;
        }else{
            k++;
        }
    }
    return b;
}

function unban(clientSender, UnbanClient, groupName){
    if (isExcluded(groupName, UnbanClient)) {
        let k = 0
        let group = findGroup(groupName)
        while (k <= group.excluded.length - 1) {
            if ( group.excluded[k] == UnbanClient) {
                break;
            }else{
                k++;
            }
        }
        group.excluded.splice(k,1);
        searchClient(UnbanClient).write(JSON.stringify({"from": clientSender,"group":groupName,
        "action":"server-send","msg":`You can join group ${groupName} again`}))
    }else{
        clientSender.write(JSON.stringify({"group":groupName,
        "action":"server-send","msg":`Receive from server : ${clientReceiver} was not bannished`}))
    }
}

function saveUser(username,plaintextPassword) {
    Bcrypt.hash(plaintextPassword, 10)
        .then(hash => {
            db.saveUser(username,hash)
        })
        .catch(err => {
            console.log(err)
        })
}

 
async function comparePassword(plaintextPassword, hash) {
    const result = await Bcrypt.compare(plaintextPassword, hash);
    return result;
}



