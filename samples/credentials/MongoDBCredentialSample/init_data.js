use('credentialdb')

//db.hmac.drop()
db.hawk.insert(
    {
        'authId': 'id123',
        'authKey': '3@uo45er?',
        'hmacAlgorithm': 'HMACSHA256',
        'hashAlgorithm': 'SHA256',
        'user': null,
        'enableServerAuthorization': true,
        'includeResponsePayloadHash': true,
        'createdTime': new Date('2022-11-05T01:00:00Z')
    }
)

db.hawk.createIndex({authId: 1}, {unique: true})

//db.hawk.find({ 'authId': 'id123' })



//db.hmac.drop()
db.hmac.insert(
    {
        'appId': 'id123',
        'appKey': '3@uo45er?',
        'hmacAlgorithm': 'HMACSHA256',
        'hashAlgorithm': 'SHA256',
        'createdTime': new Date('2022-11-05T01:00:00Z')
    }
)

db.hmac.createIndex({appId: 1}, {unique: true})

//db.hmac.find({ 'appId': 'id123' })



/*
use admin

db.system.users.remove({user: "myUserAdmin"})

db.createUser(
    {
        user: "myUserAdmin",
        pwd: "Password",
        roles: [
            { role: "userAdminAnyDatabase", db: "admin" },
            { role: "readWriteAnyDatabase", db: "admin" }
        ]
    }
)

use credentialdb
db.createUser(
    {
        user: "authreader",
        pwd: "Password",
        roles: [
            { role: "read", db: "credentialdb" },
        ]
    }
)
*/