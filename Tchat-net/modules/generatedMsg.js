
const {COMMAND_SEND,COMMAND_BROADCAST,COMMAND_LIST,COMMAND_QUIT,COMMAND_CGROUP,COMMAND_BRGROUP,
    COMMAND_JGROUP,COMMAND_MGROUP,COMMAND_LGROUP,COMMAND_HMGROUP,COMMAND_EGROUP,COMMAND_IGROUP,
    COMMAND_KGROUP,COMMAND_UGROUP,COMMAND_SGROUP,COMMAND_BGROUP,COMMAND_DELETE} = require('./command.js');

const generatedMsg = (name,client,Command)=>{

    /****************TD3*****************/

    if (Command.startsWith(COMMAND_SEND)) {
        client.write(JSON.stringify({'from': name, 'to': Command.split(";")[1] ,
        'msg': Command.split(";")[2] ,'action':'client-send'}))
    }
    if (Command.startsWith(COMMAND_BROADCAST)) {
        client.write(JSON.stringify({'from': name,'msg': Command.split(";")[1] ,
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
            'msg':  Command.split(";")[2] ,'action':'gbroadcast'})); 
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
}

module.exports = {generatedMsg}