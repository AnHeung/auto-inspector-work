require('dotenv-flow').config({
    node_env: process.env.NODE_ENV || 'dev',
    silent: true
});

const USER_ID = process.env.USER_ID;
const PW = process.env.PW;
const SERVER_PATH = process.env.SERVER_PATH;
const PATCH_FILE_NAME = 'iSecure_UnixServer_Check_v3.4.sh';
const PATCH_RECEIVE_PATH = `${SERVER_PATH}${PATCH_FILE_NAME}`;
const PORT = process.env.PORT;
const TIME_OUT = 3000;
const DEFAULT_SAVE_FOLDER = 'test'  //로컬에 저장할 폴더 위치
const WORKING_THREAD_COUNT = 1  //멀티 스레드 사용시 기본은 1개만 불안해서..
const ENCODING = 'utf-8'

module.exports= {
    USER_ID:USER_ID,
    PW:PW,
    SERVER_PATH:SERVER_PATH,
    PATCH_RECEIVE_PATH:PATCH_RECEIVE_PATH,
    PORT:PORT,
    TIME_OUT:TIME_OUT,
    DEFAULT_SAVE_FOLDER:DEFAULT_SAVE_FOLDER,
    WORKING_THREAD_COUNT:WORKING_THREAD_COUNT,
    ENCODING:ENCODING,
    PATCH_FILE_NAME:PATCH_FILE_NAME
}