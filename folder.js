const fs = require('fs');
const { NodeSSH } = require('node-ssh');
const Async = require('async');
let ssh;
const userId = 'storage_user';
const pw = 'rlvmxmdpa)()(8';
const port = 9999;
const timeOut = 3000;
const receivePath = '/home/storage_user/iSecure_UnixServer_Check_v3.4.sh';


(async () => {

    const article = fs.readFileSync("file_server_list.txt");
    const hostList = article.toString().split(',');
    console.log(hostList);

    Async.eachOfLimit(hostList, 1, async host => {
        try {
            ssh = new NodeSSH();

            const connect = await ssh.connect({
                host: host,
                username: userId,
                password: pw,
                port: port,
                readyTimeout: timeOut
            })

            if (connect) {

                await ssh
                    .putFile('./iSecure_UnixServer_Check_v3.4.sh', receivePath)
                    .catch(e => {
                        console.error(`파일 전송 실패 ${e}`)
                        fs.appendFileSync('send_error.txt', `${host}, \n`, { encoding: 'utf8' })
                        throw new Error(`파일 전송 실패 ${e}`)
                    })


                const result = await ssh.execCommand('sudo sh iSecure_UnixServer_Check_v3.4.sh',{})
                if (result) {
                    if (result.stdout) {
                        console.log(result)
                        const saveFolderPath = `./test/${host}`
                        if (!fs.existsSync(saveFolderPath)) {
                            fs.mkdirSync(saveFolderPath)
                        }
                        const receiveResult =  ssh.getFile(saveFolderPath, `/home/storage_user/CENTOS_222.239.175.226_226_storage_22-02-09_16-47-48.tar`).then((data)=>{
                            console.log(data)
                        })
                    }

                    console.log(`result ${result}`);
                }
                fs.appendFileSync('success.txt', `${host}, \n`, { encoding: 'utf8' })
            }

        } catch (e) {
            console.error(`에러 : ${e}`)
            fs.appendFileSync('error.txt', `${host}, \n`, { encoding: 'utf8' })
        } finally {
            ssh.dispose();
        }
    })
})();

