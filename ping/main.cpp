#define _WINSOCK_DEPRECATED_NO_WARNINGS //解决WINSOCK一些报错

#include<WinSock2.h>
#pragma comment(lib, "WS2_32") // 链接到WS2_32.lib
#include<iostream>

#define PACKET_SIZE 32
#define ECHO_REQUEST 8   //ICMP头部信息 判断ICMP包类别为请求还是回复
#define ECHO_REPLY 0
#define NUM_ICMP 4   //一次ping发送的包的数量
#define TIME_OUT 1000 //超时时间(ms)

struct IPHeader {
	BYTE verHLen; // 四位版本+四位首部长度
	BYTE TOS; // 服务类型
	USHORT toltalLen; // 总长度
	USHORT ID; // 标识
	USHORT flagFragOffset; // 3位标识+13位片偏移
	BYTE TTL; //TTL
	BYTE protocal; //协议
	USHORT hChecksum; // 首部校验和
	ULONG srcIP; //源IP
	ULONG destIP; //目的IP
};

struct ICMPHeader {
	BYTE type;			// 类型
	BYTE code;			// 编码
	USHORT checksum;	// 检验和
	USHORT ID;			// 编号
	USHORT seq;			// 序列号
	ULONG timeStamp;	// 时间戳
};

struct PingReply {
	USHORT seq;			// 序列号
	DWORD roundTripTime;// 往返时间
	DWORD bytes;		//字节数
	DWORD TTL;			//TTL
};

class PingAPI {
public:
	BOOL Ping(DWORD destIP, DWORD timeout, PingReply* reply);
	PingAPI();
	~PingAPI();
	
private:
	//计算校验和
	USHORT calCheckSum(USHORT* buffer, int nsize);
	ULONG getTickCountCalibrate();
	SOCKET sockRaw;
	WSAEVENT event;
	USHORT currentProcID;    //发送进程的ID 
	char* ICMPData;			//ICMP数据报
	BOOL isInitSucc;		//判断初始化是否成功
	USHORT packetSeq = 0;   //包的序列号
};


int main() {
	PingAPI pingAPI;
	char input[30];
	while (1) {
		std::cout << "\n请输入ip地址或域名:(输入exit退出)";
		std::cin >> input;
		if (!strcmp(input,"exit")) break;

		//域名解析
		hostent* hostEntry = gethostbyname(input);
		if (hostEntry == nullptr) {
			std::cout << "输入无效\n";
			continue;
		}
		char* ip = inet_ntoa(*(struct in_addr*)(hostEntry->h_addr_list[0]));
		std::cout << "\n正在 Ping " << ip << " 具有 " << PACKET_SIZE << " 字节的数据:";
		int succ_num = 0; //记录成功收到几个回复
		int mint = TIME_OUT, maxt = 0, sumt = 0; //记录最短时间 最大时间 时间和
		
		// 发4个ICMP包
		for (int i = 0; i < NUM_ICMP; i++) {
			PingReply reply;
			if (pingAPI.Ping(inet_addr(ip), TIME_OUT, &reply)) {
				std::cout << "\n来自 " << ip << " 的回复: seq=" << reply.seq << " 字节="
					<< reply.bytes << " 时间=" << reply.roundTripTime << "ms TTL=" << reply.TTL;
				succ_num++;
				mint = mint > (int)reply.roundTripTime ? (int)reply.roundTripTime : mint;
				maxt = maxt < (int)reply.roundTripTime ? (int)reply.roundTripTime : maxt;
				sumt += (int)reply.roundTripTime;
			}
			else std::cout << "\n请求超时。";
		}
		std::cout << "\n\n";
		std::cout << ip << " 的 Ping 统计信息:\n";
		printf("\t数据包: 已发送 = %d, 已接收 = %d, 丢失 = %d (%d%% 丢失),\n", 
			NUM_ICMP, succ_num, NUM_ICMP - succ_num, int(100 * (float)(NUM_ICMP - succ_num) / NUM_ICMP));
		if (succ_num != 0) {
			printf("往返行程的估计时间(以毫秒为单位):\n");
			printf("\t最短 = %dms, 最长 = %dms, 平均 = %dms\n", mint, maxt, sumt / succ_num);
		}
	}
}


BOOL PingAPI::Ping(DWORD destIP, DWORD timeout, PingReply* reply = NULL) {
	if (!isInitSucc) return FALSE; //判断初始化是否成功
	
	// 配置socket
	sockaddr_in sockaddrDest;
	sockaddrDest.sin_family = AF_INET;
	sockaddrDest.sin_addr.s_addr = destIP;
	int sockaddrDestSize = sizeof(sockaddrDest);

	//构建ICMP包
	int ICMPDataSize = PACKET_SIZE + sizeof(ICMPHeader);
	ULONG sendTimeStamp = getTickCountCalibrate();
	USHORT seq = ++packetSeq;
	memset(ICMPData, 0, ICMPDataSize);
	ICMPHeader* p = (ICMPHeader*)ICMPData;
	p->type = ECHO_REQUEST;
	p->code = 0;
	p->ID = currentProcID;
	p->seq = seq;
	p->timeStamp = sendTimeStamp;
	p->checksum = calCheckSum((USHORT*)ICMPData, ICMPDataSize);

	// 发送ICMP报文
	if (sendto(sockRaw, ICMPData, ICMPDataSize, 0, (struct sockaddr*)&sockaddrDest, sockaddrDestSize) == SOCKET_ERROR)
		return FALSE; // 发送失败

	//是否需要接受返回报文
	if (reply != NULL) {
		// 接收缓冲区
		char recvbuf[256] = { '\0' };
		// 这里一定要while，因为recvbuf 会接受到很多报文，包括发送出去的报文
		while (TRUE) {
			//接收响应报文
			if (WSAWaitForMultipleEvents(1, &event, FALSE, 100, FALSE) != WSA_WAIT_TIMEOUT) {
				WSANETWORKEVENTS netEvent;
				WSAEnumNetworkEvents(sockRaw, event, &netEvent);
				if (netEvent.lNetworkEvents & FD_READ) {
					ULONG recvTimeStamp = getTickCountCalibrate();
					int packetSize = recvfrom(sockRaw, recvbuf, 256, 0, (struct sockaddr*)&sockaddrDest, &sockaddrDestSize);
					if (packetSize != SOCKET_ERROR) {
						IPHeader* pIPHeader = (IPHeader*)recvbuf;
						USHORT IPHeaderLen = (USHORT)((pIPHeader->verHLen & 0x0f) * 4);
						ICMPHeader* pICMPHeader = (ICMPHeader*)(recvbuf + IPHeaderLen);
						// 判断是要接收的报文
						if (pICMPHeader->ID == currentProcID && pICMPHeader->type == ECHO_REPLY && pICMPHeader->seq == seq) {
							reply->seq = seq;
							reply->roundTripTime = recvTimeStamp - pICMPHeader->timeStamp;
							reply->bytes = packetSize - IPHeaderLen - sizeof(ICMPHeader);
							reply->TTL = pIPHeader->TTL;
							return true;
						}
					}
				}
			}
			// 判断超时
			if (getTickCountCalibrate() - sendTimeStamp >= timeout)
				return FALSE;
		}
	}
	else return TRUE;
}



USHORT PingAPI::calCheckSum(USHORT* buffer, int nsize) {
	unsigned long checkSum = 0;
	while (nsize > 1) {
		checkSum += *buffer++;
		nsize -= sizeof(USHORT);
	}
	if (nsize) checkSum += *(UCHAR*)buffer;
	checkSum = (checkSum >> 16) + (checkSum & 0xffff);
	checkSum += checkSum >> 16;
	return (USHORT)(~checkSum);
}

ULONG PingAPI::getTickCountCalibrate()
{
	static ULONG firstCallTick = 0;
	static LONGLONG firstCallTickMS = 0;

	SYSTEMTIME systemtime;
	FILETIME filetime;
	
	//检索当前本地日期和时间
	GetLocalTime(&systemtime);
	//将系统时间转换为文件格式
	SystemTimeToFileTime(&systemtime, &filetime);
	LARGE_INTEGER currentTime;
	currentTime.HighPart = filetime.dwHighDateTime;
	currentTime.LowPart = filetime.dwLowDateTime;
	LONGLONG currentTimeMS = currentTime.QuadPart / 10000;

	if (firstCallTick == 0) firstCallTick = GetTickCount();
	if (firstCallTickMS == 0) firstCallTickMS = currentTimeMS;

	return firstCallTick + (ULONG)(currentTimeMS - firstCallTickMS);
}


inline PingAPI::PingAPI() {
	WSADATA WSAData;
	if (WSAStartup(MAKEWORD(1, 1), &WSAData) != 0) std::cerr << GetLastError();

	event = WSACreateEvent();
	currentProcID = (USHORT)GetCurrentProcessId();
	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, 0);

	if (sockRaw == INVALID_SOCKET) std::cerr << WSAGetLastError();
	WSAEventSelect(sockRaw, event, FD_READ);
	isInitSucc = TRUE;
	ICMPData = (char*)malloc(PACKET_SIZE + sizeof(ICMPHeader));
	if (ICMPData == NULL) isInitSucc = FALSE;
}

inline PingAPI::~PingAPI() {
	WSACleanup();
	if (ICMPData != NULL) {
		free(ICMPData);
		ICMPData = NULL;
	}
}