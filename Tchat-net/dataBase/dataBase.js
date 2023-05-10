const sqlite = require('sqlite-sync')
sqlite.connect('../dataBase/tchat.sqlite')


class database{

    getAllUser(){
        return sqlite.run("SELECT * FROM user")
    }

    getUserByName(name){
        return sqlite.run("SELECT username FROM user WHERE username = '"+name+"'")[0].username

    }

    getAllgroup(){
        return sqlite.run("SELECT Id, group_name, type FROM groupe")
    }

    findIdUserByName(name){
        return sqlite.run("SELECT Id FROM user WHERE username = '"+name+"'")[0].Id
    }

    findUserNameById(Id){
        return sqlite.run("SELECT username FROM user WHERE Id = "+Id)[0].username
    }

    findUserNameByName(name){
        return sqlite.run("SELECT username FROM user WHERE username ='"+name+"'")
    }

    getPasswordUserByName(name){
        return sqlite.run("SELECT password FROM user WHERE username ='"+name+"'")[0].password
    }

    saveUser(name,pwd){
        sqlite.insert("user",{username:name, password:pwd},res=>{
            if(res.err){
                console.log(res.err)
            }
            console.log('successful registration')
        })
    }

    updateStatus(name, status){
        sqlite.update("user",{status:status},{Id:this.findIdUserByName(name)})  
    }

    saveGroup(group_name,type){
        let date = new Date().getTime()
        sqlite.insert("groupe",{group_name:group_name, type:type, create_at:date},res=>{
            if(res.err){
                console.log(res.err)
            }
            console.log('successful registration')
        })
    }

    findIdGroupByName(group_name){
        return sqlite.run("SELECT Id FROM groupe WHERE group_name = '"+group_name+"'")[0].Id
    }

    findNameGroupById(Id){
        return sqlite.run("SELECT group_name, type FROM groupe WHERE Id = '"+Id+"'")[0]
    }

    getMembersGroup(Id){
        return sqlite.run("SELECT username FROM user u JOIN user_group ug ON u.Id = ug.Id_user WHERE ug.Id_group = "+Id)
    }

    saveState(event,group_name){
        let Id_group = this.findIdGroupByName(group_name)
        sqlite.insert("state",{event:event, Id_group:Id_group},res=>{
            if(res.err){
                console.log(res.err)
            }
            console.log('successful registration')
        })
    }

    getStateGroup(Id){
        return sqlite.run("SELECT event FROM state WHERE Id_group =" +Id)
    }

    getGroupMsg(Id){
        return sqlite.run("SELECT Id_user, content FROM msg WHERE Id_group =" +Id)
    }

    getUserMsgReceived(name){
        return sqlite.run("SELECT Id_user, Id_group, content FROM msg WHERE receiver = '"+ name+"'")
    }

    saveMsg(sender,receiver,msg,group_name){
        let Id_user = this.findIdUserByName(sender)
        let Id_group = ''
        if (group_name != '') {
            Id_group = this.findIdGroupByName(group_name)
        }
        sqlite.insert("msg",{receiver:receiver,content:msg, Id_group:Id_group,
            Id_user:Id_user},res=>{
            if(res.err){
                console.log(res.err)
            }
            console.log('successful registration')
        })
    }

    saveUserGroup(username, group_name){
        let Id_user = this.findIdUserByName(username)
        let Id_group = this.findIdGroupByName(group_name)
        sqlite.insert("user_group",{Id_group:Id_group, Id_user:Id_user}, res=>{
            if(res.err){
                console.log(res.err)
            }
            console.log('successful registration')
        })
    }

    Login(name, pwd){
        let b = false
        let login = sqlite.run("SELECT username FROM user WHERE username = '"+name+"'"+"AND password = '"+pwd+"'");
        if (login.length>=1) {
            b = !b;
        }
        return b;
    }

    invitedGroup(username, group_name){
        let Id_user = this.findIdUserByName(username)
        let Id_group = this.findIdGroupByName(group_name)
        sqlite.insert("user_group_invite",{Id_group:Id_group, Id_user:Id_user}, res=>{
            if(res.err){
                console.log(res.err)
            }
            console.log('successful registration')
        })
    }

    getListGroupGuests(Id){
        return sqlite.run("SELECT username FROM (groupe g JOIN user_group_invite i ON g.id = i.Id_group) JOIN user u ON u.id = i.Id_user WHERE i.Id_group ="+Id)
    }

    bannishedGroup(username, group_name){
        let Id_user = this.findIdUserByName(username)
        let Id_group = this.findIdGroupByName(group_name)
        sqlite.insert("user_group_bannish",{Id_group:Id_group, Id_user:Id_user}, res=>{
            if(res.err){
                console.log(res.err)
            }
            console.log('successful registration')
        })
    }

    getListBannedGroup(Id){
        return sqlite.run("SELECT username FROM (groupe g JOIN user_group_bannish b ON g.id = b.Id_group) JOIN user u ON u.id = b.Id_user WHERE b.Id_group ="+Id)
    }

    unbannishedGroup(username, group_name){
        let Id_user = this.findIdUserByName(username)
        let Id_group = this.findIdGroupByName(group_name)
        sqlite.delete("user_group_bannish",{Id_group:Id_group, Id_user:Id_user}, res=>{
            if(res.err){
                console.log(res.err)
            }
        })
    }

    leaveGroup(username, group_name){
        let Id_user = this.findIdUserByName(username)
        let Id_group = this.findIdGroupByName(group_name)
        sqlite.delete("user_group",{Id_user:Id_user,Id_group:Id_group}, res=>{
            if(res.err){
                console.log(res.err)
            }
        })
    }

    deleteSession(name){
        let Id = this.findIdUserByName(name)
        sqlite.delete("user",{Id:Id}, res=>{
            if(res.err){
                console.log(res.err)
            }
        }) 
        sqlite.delete("msg",{receiver:name}, res=>{
            if(res.err){
                console.log(res.err)
            }
        })
    }

}

module.exports = new database(sqlite)