#define _WINSOCK_DEPRECATED_NO_WARNINGS //���WINSOCKһЩ����

#include<WinSock2.h>
#pragma comment(lib, "WS2_32") // ���ӵ�WS2_32.lib
#include<iostream>

#define PACKET_SIZE 32
#define ECHO_REQUEST 8   //ICMPͷ����Ϣ �ж�ICMP�����Ϊ�����ǻظ�
#define ECHO_REPLY 0
#define NUM_ICMP 4   //һ��ping���͵İ�������
#define TIME_OUT 1000 //��ʱʱ��(ms)

struct IPHeader {
	BYTE verHLen; // ��λ�汾+��λ�ײ�����
	BYTE TOS; // ��������
	USHORT toltalLen; // �ܳ���
	USHORT ID; // ��ʶ
	USHORT flagFragOffset; // 3λ��ʶ+13λƬƫ��
	BYTE TTL; //TTL
	BYTE protocal; //Э��
	USHORT hChecksum; // �ײ�У���
	ULONG srcIP; //ԴIP
	ULONG destIP; //Ŀ��IP
};

struct ICMPHeader {
	BYTE type;			// ����
	BYTE code;			// ����
	USHORT checksum;	// �����
	USHORT ID;			// ���
	USHORT seq;			// ���к�
	ULONG timeStamp;	// ʱ���
};

struct PingReply {
	USHORT seq;			// ���к�
	DWORD roundTripTime;// ����ʱ��
	DWORD bytes;		//�ֽ���
	DWORD TTL;			//TTL
};

class PingAPI {
public:
	BOOL Ping(DWORD destIP, DWORD timeout, PingReply* reply);
	PingAPI();
	~PingAPI();
	
private:
	//����У���
	USHORT calCheckSum(USHORT* buffer, int nsize);
	ULONG getTickCountCalibrate();
	SOCKET sockRaw;
	WSAEVENT event;
	USHORT currentProcID;    //���ͽ��̵�ID 
	char* ICMPData;			//ICMP���ݱ�
	BOOL isInitSucc;		//�жϳ�ʼ���Ƿ�ɹ�
	USHORT packetSeq = 0;   //�������к�
};


int main() {
	PingAPI pingAPI;
	char input[30];
	while (1) {
		std::cout << "\n������ip��ַ������:(����exit�˳�)";
		std::cin >> input;
		if (!strcmp(input,"exit")) break;

		//��������
		hostent* hostEntry = gethostbyname(input);
		if (hostEntry == nullptr) {
			std::cout << "������Ч\n";
			continue;
		}
		char* ip = inet_ntoa(*(struct in_addr*)(hostEntry->h_addr_list[0]));
		std::cout << "\n���� Ping " << ip << " ���� " << PACKET_SIZE << " �ֽڵ�����:";
		int succ_num = 0; //��¼�ɹ��յ������ظ�
		int mint = TIME_OUT, maxt = 0, sumt = 0; //��¼���ʱ�� ���ʱ�� ʱ���
		
		// ��4��ICMP��
		for (int i = 0; i < NUM_ICMP; i++) {
			PingReply reply;
			if (pingAPI.Ping(inet_addr(ip), TIME_OUT, &reply)) {
				std::cout << "\n���� " << ip << " �Ļظ�: seq=" << reply.seq << " �ֽ�="
					<< reply.bytes << " ʱ��=" << reply.roundTripTime << "ms TTL=" << reply.TTL;
				succ_num++;
				mint = mint > (int)reply.roundTripTime ? (int)reply.roundTripTime : mint;
				maxt = maxt < (int)reply.roundTripTime ? (int)reply.roundTripTime : maxt;
				sumt += (int)reply.roundTripTime;
			}
			else std::cout << "\n����ʱ��";
		}
		std::cout << "\n\n";
		std::cout << ip << " �� Ping ͳ����Ϣ:\n";
		printf("\t���ݰ�: �ѷ��� = %d, �ѽ��� = %d, ��ʧ = %d (%d%% ��ʧ),\n", 
			NUM_ICMP, succ_num, NUM_ICMP - succ_num, int(100 * (float)(NUM_ICMP - succ_num) / NUM_ICMP));
		if (succ_num != 0) {
			printf("�����г̵Ĺ���ʱ��(�Ժ���Ϊ��λ):\n");
			printf("\t��� = %dms, � = %dms, ƽ�� = %dms\n", mint, maxt, sumt / succ_num);
		}
	}
}


BOOL PingAPI::Ping(DWORD destIP, DWORD timeout, PingReply* reply = NULL) {
	if (!isInitSucc) return FALSE; //�жϳ�ʼ���Ƿ�ɹ�
	
	// ����socket
	sockaddr_in sockaddrDest;
	sockaddrDest.sin_family = AF_INET;
	sockaddrDest.sin_addr.s_addr = destIP;
	int sockaddrDestSize = sizeof(sockaddrDest);

	//����ICMP��
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

	// ����ICMP����
	if (sendto(sockRaw, ICMPData, ICMPDataSize, 0, (struct sockaddr*)&sockaddrDest, sockaddrDestSize) == SOCKET_ERROR)
		return FALSE; // ����ʧ��

	//�Ƿ���Ҫ���ܷ��ر���
	if (reply != NULL) {
		// ���ջ�����
		char recvbuf[256] = { '\0' };
		// ����һ��Ҫwhile����Ϊrecvbuf ����ܵ��ܶ౨�ģ��������ͳ�ȥ�ı���
		while (TRUE) {
			//������Ӧ����
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
						// �ж���Ҫ���յı���
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
			// �жϳ�ʱ
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
	
	//������ǰ�������ں�ʱ��
	GetLocalTime(&systemtime);
	//��ϵͳʱ��ת��Ϊ�ļ���ʽ
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