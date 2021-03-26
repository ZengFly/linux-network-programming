#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define LEN (6)
#define DATA ("12345")
#define MTU (1500)
#define RECV_TIMEOUT_USEC (100000)

struct icmp_data{
    /*公共头部*/
    uint8_t type;       /*类型*/
    uint8_t code;       /*代码*/
    uint16_t checksum;  /*校验和*/
    /*惯例头部*/
    uint16_t ident;     /*回显请求*/
    uint16_t seq;       /*回显回复*/
    /*数据负载*/
    double timestamp;       /*时间戳*/
    char other[LEN];
};

double get_timestamp();     /*获取时间戳*/
uint16_t calc_checksum(unsigned char* buffer, int bytes);  /*计算校验和*/
int send_request(int sock, struct sockaddr_in* addr, int ident, int seq);
int recv_response(int sock, int ident);

/*检查IP是否可以连通*/
int ping(const char *ip){
    if (ip == NULL) {
        return -1;
    }
    struct sockaddr_in addr;

    //填充addr
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        printf("ip addr error\n");
        return -1;
    }
    printf("%X\n", addr.sin_addr.s_addr);
    //建立socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        return -1;
    }
    //设置超时
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = RECV_TIMEOUT_USEC;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        printf("setsockopt error\n");
        close(sock);
        return -1;
    }

    double next_ts = get_timestamp();
    int ident = getpid();
    int seq = 1;
    int ret;

    for (;;) {
        if (get_timestamp() >= next_ts) {
            printf("Send request\n");
            ret = send_request(sock, &addr, ident, seq);
            if (ret == -1) {
                perror("Send failed");
            }

            next_ts += 1;
            seq += 1;
            
            printf("Recv response\n");
            ret = recv_response(sock, ident);
            if (ret == 1) {
              printf("Received response data.\n");
            //return 0;
            }
        }
    }

    return -1;
}

double get_timestamp()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + ((double)tv.tv_usec) / 1000000;
}

/*计算ICMP数据校验和*/
uint16_t calc_checksum(unsigned char* buffer, int bytes){
    uint32_t checksum = 0;
    unsigned char *end = buffer + bytes;

    //加最后一个数据
    if (bytes % 2 == 1) {
        end = buffer + bytes - 1;   /*取最后一个单数据*/
        checksum += (*end) << 8;    /*先加最后一个数据(补0变成双字节)*/
    }
    //依次相加其他数据
    while (buffer < end) {
        checksum += buffer[0] << 8;
        checksum += buffer[1];
        buffer += 2;
    }
    //高于16位的进位相加
    uint32_t carry = checksum >> 16;
    while (carry) {
        checksum = (checksum & 0xffff) + carry;
        carry = checksum >> 16;
    }
    //结果按位取反
    checksum = ~checksum;

    return checksum;
}


int send_request(int sock, struct sockaddr_in* addr, int ident, int seq){
    struct icmp_data icmp;
    bzero(&icmp, sizeof(icmp));
    //填充数据
    /*
     类型0、代码0：回应应答。
    类型3、代码0：网络不可达
    类型3、代码1：主机不可达
    类型5、代码1：为主机重定向数据包
    类型8、代码0：回应
    类型11、代码0：传输中超出TTL（常说的超时）
     */
    icmp.type = 8;
    icmp.code = 0;
    icmp.ident = htons(ident);
    icmp.seq = htons(seq);
    icmp.timestamp = get_timestamp();
    strncpy(icmp.other, DATA, LEN);
    //计算校验和
    icmp.checksum = htons(calc_checksum((unsigned char *) &icmp, sizeof(icmp)));
    //发送数据
    int ret = sendto(sock,&icmp, sizeof(icmp),0,(struct sockaddr *)addr,sizeof(*addr));
    if (ret < 0) {
        return -1;
    }

    return 0;
}

int recv_response(int sock, int ident){
    char buffer[MTU];
    struct sockaddr_in remote_addr;

    //接收数据
    socklen_t addr_len = sizeof(remote_addr);
    errno = 0;
    int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&remote_addr, &addr_len);
    if (bytes == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("Recv errno = %d\n", errno);
            return 0;
        }
        printf("Recv error\n");
        return -1;
    }
    //处理ICMP数据
    struct icmp_data *icmp= (struct icmp_data *)(buffer + 20);
    if (icmp->type != 0 || icmp->code != 0) {
        return 0;
    }
    if (ntohs(icmp->ident) != ident) {
        return 0;
    }

    printf("%s seq=%d %5.2fms\n",
           inet_ntoa(remote_addr.sin_addr),
           ntohs(icmp->seq),
           (get_timestamp() - icmp->timestamp) * 1000
    );

    return 1;
}

int main(int argc, const char* argv[])
{
    return ping(argv[1]);
}
