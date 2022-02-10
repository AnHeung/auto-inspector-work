const fs = require('fs');
const { NodeSSH } = require('node-ssh'); //ssh 라이브러리
const Client = require('ssh2-sftp-client'); //sftp 라이브러리
const Async = require('async');
const { USER_ID, PW, SERVER_PATH, PATCH_RECEIVE_PATH, TIME_OUT, PORT, WORKING_THREAD_COUNT, DEFAULT_SAVE_FOLDER, ENCODING, PATCH_FILE_NAME } = require('./app_constants');
const ssh = new NodeSSH(); // ssh 접속 및 shell 명령
const sftp = new Client(); //sftp 파일전송

//텍스트 파일로 저장
const saveTxtFile =  (txtFileName , msg)=> fs.appendFileSync(txtFileName, msg, { encoding: ENCODING })

//로컬에 폴더 생성
const makeFolder = (path) => {
    if (!fs.existsSync(path)) {
        fs.mkdirSync(path, { recursive: true })
    }
}

//패치 파일 서버로 전송
const pathFileSendLocalToServer = async (host , local, server) => 
      ssh
        .putFile(local, server)
        .catch(e => {
            console.error(`패치 파일 전송 실패 ${e}`)
            saveTxtFile('send_error.txt', `${host},`)
            throw new Error(`패치 파일 전송 실패 ${e}`)
        })

// SSH 접속
const connectSSH = async(host)=> ssh.connect({
    host: host,
    username: USER_ID,
    password: PW,
    port: PORT,
    readyTimeout: TIME_OUT
})

//실행시 txt 파일 초기화
const clearTextFile = ()=>{
    if(fs.existsSync("error.txt")) fs.unlinkSync('error.txt')
    if(fs.existsSync("success.txt")) fs.unlinkSync('success.txt')
    if(fs.existsSync("send_error.txt")) fs.unlinkSync('send_error.txt')
}

//쉘 스크립트 실행
const executeShellCommand = async(command) => ssh.execCommand(command, {})

// 완료된 패치 파일 서버에서 로컬로 저장
const patchSuccessFileServerToLocal = async (host, serverPath , saveLocalPath)=>
    sftp.connect({
        host: host,
        port: PORT,
        username: USER_ID,
        password: PW
    })
        .then(() => sftp.list(serverPath))
        .then(data => {
            const downFileName = data
                .map(({ name }) => name)
                .find(name => name.includes('CENTOS'))

            return sftp.get(`${serverPath}${downFileName}`, fs.createWriteStream(`${saveLocalPath}/${downFileName}`))
        })
        .then(() => sftp.end())
        .catch(err => {
            console.log(err, 'catch error');
        });


(async () => {

    const fileServerList = fs.readFileSync("file_server_list.txt");
    const hostList = fileServerList.toString().split(',');
    console.log(`작업할 서버 목록 : ${hostList}`);

    clearTextFile();

    Async.eachOfLimit(hostList, WORKING_THREAD_COUNT, async host => {
        try {
            const connect = await connectSSH(host)

            if (connect) {
                await pathFileSendLocalToServer(host ,PATCH_FILE_NAME, PATCH_RECEIVE_PATH)
                const result = await executeShellCommand('sudo sh iSecure_UnixServer_Check_v3.4.sh')
                if (result && result.stdout) {
                    const saveFolderPath = `${DEFAULT_SAVE_FOLDER}/${host}`
                    makeFolder(saveFolderPath);
                    await patchSuccessFileServerToLocal(host, SERVER_PATH , saveFolderPath)
                    saveTxtFile('success.txt', `${host},`)    
                    console.log(`${host} 서버 작업 완료`)
                }
            }
        } catch (e) {
            console.error(`${host} 서버 에러 : ${e}`)
            saveTxtFile('error.txt', `${host},`)   
        } finally {
            if (ssh) ssh.dispose();
        }
    })
})();

