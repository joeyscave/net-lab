#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 *
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 *
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    udp_hdr_t *udp_header = (udp_hdr_t *)buf->data;
    uint8_t *ori_udp_head = buf->data;

    // add udp pseudo-header
    buf_add_header(buf, sizeof(udp_peso_hdr_t));

    // save ip header
    buf_t tmpbuf;
    buf_t *ip_hdr_buf = &tmpbuf; // use a temp buf to save ip header
    buf_init(ip_hdr_buf, sizeof(ip_hdr_t));
    memcpy(ip_hdr_buf->data, ori_udp_head - sizeof(ip_hdr_t), sizeof(ip_hdr_t)); // data-IP_header(20)=>udpdata
    ip_hdr_t *ip_hdr_save = (ip_hdr_t *)ip_hdr_buf->data;

    // fill in the 12-byte field of the UDP pseudo-header
    udp_peso_hdr_t *peso_header = (udp_peso_hdr_t *)buf->data;
    memcpy(peso_header->dst_ip, ip_hdr_save->dst_ip, NET_IP_LEN);
    memcpy(peso_header->src_ip, ip_hdr_save->src_ip, NET_IP_LEN);
    peso_header->placeholder = 0;
    peso_header->protocol = ip_hdr_save->protocol;
    peso_header->total_len16 = udp_header->total_len16;

    // if udp data length is odd, add a padding byte
    int odd = 0;
    if (buf->len % 2 == 1){
        odd = 1;
        buf_add_padding(buf, 1);
    }

    // calculate UDP checksum
    uint16_t checksum = checksum16((uint16_t *)buf->data, buf->len);

    // copy back saved ip_header
    memcpy(ori_udp_head - sizeof(ip_hdr_t), ip_hdr_buf->data, sizeof(ip_hdr_t));

    // remove udp peso header and padding byte
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));
    if (odd)
        buf_remove_padding(buf, 1);
    return checksum;
}

/**
 * @brief 处理一个收到的udp数据包
 *
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    if (buf->len < sizeof(udp_hdr_t))
        return;
    udp_hdr_t *udp_hdr = (udp_hdr_t *)buf->data;
    uint16_t checksum16 = udp_hdr->checksum16;
    udp_hdr->checksum16 = 0;
    if (checksum16 != udp_checksum(buf, src_ip, net_if_ip))
        return;
    uint16_t key = swap16(udp_hdr->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &key);
    if (handler == NULL)
    {
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, src_ip, ICMP_CODE_PORT_UNREACH);
        return;
    }
    else
    {
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (*handler)(buf->data, buf->len, src_ip, swap16(udp_hdr->src_port16));
    }
}

/**
 * @brief 处理一个要发送的数据包
 *
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // add udp header
    buf_add_header(buf, sizeof(udp_hdr_t));
    udp_hdr_t *udp_header = (udp_hdr_t *)buf->data;

    // fill in udp header
    udp_header->src_port16 = swap16(src_port);
    udp_header->dst_port16 = swap16(dst_port);
    udp_header->total_len16 = swap16(buf->len);
    udp_header->checksum16 = 0;

    // calculate checksum
    uint8_t src_ip[NET_IP_LEN] = NET_IF_IP;
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_header = (ip_hdr_t *)buf->data;
    ip_header->protocol = NET_PROTOCOL_UDP;
    memcpy(ip_header->src_ip, src_ip, sizeof(uint8_t)*NET_IP_LEN);
    memcpy(ip_header->dst_ip, dst_ip, sizeof(uint8_t)*NET_IP_LEN);
    buf_remove_header(buf, sizeof(ip_hdr_t));
    uint16_t checksum = udp_checksum(buf, src_ip, dst_ip);
    udp_header->checksum16 = checksum;

    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 *
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 *
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    printf("udp open\n");
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 *
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    printf("udp close\n");
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 *
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}