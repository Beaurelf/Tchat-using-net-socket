var net = require('net');
var client = new net.Socket();
const {COMMAND_SEND,COMMAND_BROADCAST,COMMAND_LIST,COMMAND_QUIT,COMMAND_CGROUP,COMMAND_BRGROUP,
    COMMAND_JGROUP,COMMAND_MGROUP,COMMAND_LGROUP,COMMAND_HMGROUP,COMMAND_EGROUP,COMMAND_IGROUP,
    COMMAND_KGROUP,COMMAND_UGROUP,COMMAND_SGROUP,COMMAND_BGROUP,COMMAND_DELETE} = require('./../modules/command');

const process = require('node:process');
var PORT = '';
var HOST = '';
var name = '';
var pwd = '';

var yargs = require('yargs');
const Crypto = require('crypto')
const aes256 = require('aes256');


const ClientServer = Crypto.createECDH('secp256k1');
ClientServer.generateKeys(); 
const ClientPublicKeyBase64 = ClientServer.getPublicKey().toString('base64');
var ClientSharedKey = null


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

const readline = require('readline');
const rl = readline.createInterface(process.stdin, process.stdout);

client.connect(PORT, HOST, function() {
    client.write(JSON.stringify({'data': ClientPublicKeyBase64, 'action':'client-key'}));        
    rl.question('Do you want to signIn ou logIn ? 0 for SignIn and 1 for LogIn ',choice=>{
        if(choice == 0){
            rl.question('Please enter your username ? : ', (n)=>{
                name = n
                rl.prompt(true)
                rl.question('Please enter a password ? : ', (p)=>{
                    pwd = aes256.encrypt(ClientSharedKey,p)
                    rl.prompt(true)
                    client.write(JSON.stringify({'from' : name, 'pwd':pwd, 'action' : 'client-hello'}));
                    client.write(JSON.stringify({'from': name,'error':'connected','action':'client-error'}));        
                })
            })
        }else if(choice == 1){
            rl.question('Please enter your username ? : ', (n)=>{
                name = n
                rl.prompt(true)
                rl.question('Please enter your password ? : ', (p)=>{
                    pwd = aes256.encrypt(ClientSharedKey,p)
                    rl.prompt(true)
                    client.write(JSON.stringify({'from' : name, 'pwd':pwd, 'action' : 'client-hello', 'login':true}));
                })
            })
        }
    })
    rl.prompt(true)
});

client.on('data', function(data) {
    msg = JSON.parse(data);
    switch(msg.action){
        case'server-key':
            ClientSharedKey = ClientServer.computeSecret(msg.data, 'base64', 'hex');
            break;
        case 'server-hello':
            process.stdout.write('Received from server : ' + msg.msg+'\n');
            if(msg.data){
                process.stdout.write(' session restore ....\n');
                msg.data.map(m=>{
                    if(m.group == ''){
                        process.stdout.write('Received from '+m.from+' : ' + m.content+'\n');
                    }else{
                        process.stdout.write('group '+m.group+'Received from '+m.from+' : ' + msg.content+'\n');
                    }
                })
                process.stdout.write(' restoration finished ....\n');
            }
            break;
        case 'server-send':
            if(msg.group){
                process.stdout.write('group '+msg.group+' ' + msg.msg+'\n');
            }else{
                process.stdout.write('Received from '+msg.from+' : ' + msg.msg+'\n');
            }
            break;
        case 'server-send-error':
            process.stdout.write(msg.msg+'\n');
            break;
        case 'server-broadcast':
            process.stdout.write(msg.msg+'\n');
            break;
        case 'server-list-clients':
            process.stdout.write("List of client : \n");
            msg.data.map(c=>{
                process.stdout.write(c+'\n')  
            })
            break;
        case 'server-quit':
            rl.close()
            break;
        case 'server-client-quit':
            process.stdout.write(msg.msg+ '\n');
            break;
        case 'server-error':
            process.stdout.write(msg.msg+ '\n');
            break;
        case 'server-cgroup':
            process.stdout.write('Received from server : ' +msg.msg+ '\n');
            break;
        case 'server-jgroup':
            process.stdout.write('Received from server : ' + msg.msg + '\n');
            break;
        case 'server-jgroup-already':
            process.stdout.write('Received from server : ' + msg.msg + '\n');
            break;
        case 'server-group-not-exist':
            process.stdout.write('Received from server : ' + msg.msg + '\n');
            break;
        case 'server-gbroadcast':
            process.stdout.write('group ' +msg.group+' '+ msg.msg+'\n');
            break;
        case 'server-members-group':
            process.stdout.write(msg.group+"'s members: \n");
            msg.data.map(c=>{
                process.stdout.write(c + '\n')  
            })
            break;
        case 'server-groups':
            process.stdout.write("List of group : \n");
            msg.data.map(g=>{
                process.stdout.write(g+'\n');  
            })
            break;
        case 'server-msgs':
            process.stdout.write('Group '+msg.group +' message list : \n');
            msg.data.map(m=>{
                process.stdout.write(m.from+' : '+m.content+'\n');  
            })
            break;
        case 'server-states':
            process.stdout.write('Group '+msg.group +' states : \n');
            msg.data.map(s=>{
                process.stdout.write(s+'\n');  
            })
            break;
        default:
            process.stdout.write('Received from server : ' + msg.msg + '\n');
    }
    process.stdout.write('> ');
});

rl.on('line', (Command)=>{
    if (Command.startsWith(COMMAND_SEND)) {
        client.write(JSON.stringify({'from': name, 'to': Command.split(";")[1] ,
        'msg': aes256.encrypt(ClientSharedKey,Command.split(";")[2]) ,'action':'client-send'}))
    }
    if (Command.startsWith(COMMAND_BROADCAST)) {
        client.write(JSON.stringify({'from': name,'msg': aes256.encrypt(ClientSharedKey,Command.split(";")[1]) ,
        'action':'client-broadcast'}))
    }
    if (Command.startsWith(COMMAND_LIST)) {
        client.write(JSON.stringify({'from': name,'msg': Command.split(";")[1] ,
        'action':'client-list-clients'}))
    }
    if (Command.startsWith(COMMAND_QUIT)) {
        client.write(JSON.stringify({'from': name,'action':'client-quit'}));
        
    }

    /****************TD4*****************/

    if (Command.startsWith(COMMAND_CGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'type':Command.split(";")[2],'action':'cgroup'}));
    }
    if (Command.startsWith(COMMAND_JGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'action':'join'}));
        
    }
    if (Command.startsWith(COMMAND_BRGROUP)) {
        client.write(JSON.stringify({'sender': name ,'group':  Command.split(";")[1], 
            'msg':  aes256.encrypt(ClientSharedKey,Command.split(";")[2]) ,'action':'gbroadcast'})); 
    }
    if (Command.startsWith(COMMAND_MGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'action':'members'}));  
    }
    if (Command.startsWith(COMMAND_LGROUP)) {
        client.write(JSON.stringify({'sender': name,'action':'groups'}));  
    }
    if (Command.startsWith(COMMAND_HMGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'action':'msgs'}));
    }
    if (Command.startsWith(COMMAND_EGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'action':'leave'}));
    }
    if (Command.startsWith(COMMAND_IGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'dest':Command.split(";")[2],'action':'invite'}));
    }
    if (Command.startsWith(COMMAND_KGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'dest':Command.split(";")[2],'reason':Command.split(";")[3],'action':'kick'}));
    }
    if (Command.startsWith(COMMAND_UGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'dest':Command.split(";")[2],'action':'unban'}));
    }
    if (Command.startsWith(COMMAND_BGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'dest':Command.split(";")[2],'reason':Command.split(";")[3],'action':'ban'}));
    }
    if (Command.startsWith(COMMAND_SGROUP)) {
        client.write(JSON.stringify({'sender': name, 'group': Command.split(";")[1] ,
        'action':'states'}));
    }
    if (Command.startsWith(COMMAND_DELETE)) {
        client.write(JSON.stringify({'sender': name, 'action':'delete'}));
    }
    process.stdout.write('> ');
})

rl.on('SIGINT', ()=>{
    client.write(JSON.stringify({'from': name,'error':'disconnected','action':'client-error'}));
})

