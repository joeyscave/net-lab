#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // 如果数据包的长度小于IP头部长度，丢弃不处理
    if (buf->len < sizeof(ip_hdr_t))
        return;

    ip_hdr_t *ip_h = (ip_hdr_t *)buf->data;
    // 报头捡查
    // ip头部版本号是否为IPv4
    if (ip_h->version != IP_VERSION_4)
        return;
    // 总长度字段小于或等于收到的包的长度（IP数据报的最大长度为65535字节）
    if (ip_h->total_len16 > swap16(65535))
        return;

    // 检验头部校验和(校验和无须大小端转化)
    // 先把头部校验和用其他变量保存并将校验和置0
    uint16_t ip_check_sum = ip_h->hdr_checksum16;
    ip_h->hdr_checksum16 = 0;
    // 调用checksum16计算头部校验和，若不一致则丢弃，一致则恢复
    if (ip_check_sum != checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t)))
        return;
    ip_h->hdr_checksum16 = ip_check_sum;

    // 对比目的IP地址是否为本机IP地址，若不是则丢弃不处理
    if (memcmp(net_if_ip, ip_h->dst_ip, NET_IP_LEN) != 0)
        return;

    // 如果接收到的数据包的长度大于IP头部的总长度字段
    // 则说明该数据包有填充字段
    // 可调用buf_remove_padding()函数去除填充字段。
    if (swap16(ip_h->total_len16) < buf->len)
        buf_remove_padding(buf, buf->len - swap16(ip_h->total_len16));

    // 向上层协议传递
    if (ip_h->protocol == NET_PROTOCOL_ICMP || ip_h->protocol == NET_PROTOCOL_UDP)
    {
        // 调用buf_remove_header去除ip报头
        buf_remove_header(buf, sizeof(ip_hdr_t));
        // 调用net_in()函数向上层传递数据包
        net_in(buf, ip_h->protocol, ip_h->src_ip);
    }
    else
        icmp_unreachable(buf, ip_h->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // 调用buf_add_header()增加IP数据报头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));

    // 填写IP数据报头部字段
    ip_hdr_t *ip_h = (ip_hdr_t *)buf->data;

    ip_h->version = IP_VERSION_4;
    ip_h->hdr_len = 5;
    ip_h->tos = 0;
    ip_h->total_len16 = swap16(buf->len);
    ip_h->id16 = swap16(id);
    if (mf)
        ip_h->flags_fragment16 = swap16(IP_MORE_FRAGMENT | offset);
    else
        ip_h->flags_fragment16 = swap16(offset);
    ip_h->ttl = IP_DEFALUT_TTL;
    ip_h->protocol = protocol;
    memcpy(ip_h->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_h->dst_ip, ip, NET_IP_LEN);

    // 先把IP头部的首部校验和字段填0
    // 再调用checksum16函数计算校验和
    // 然后把计算出来的校验和填入首部校验和字段
    ip_h->hdr_checksum16 = 0;
    ip_h->hdr_checksum16 = checksum16((uint16_t *)buf->data, sizeof(ip_hdr_t));

    // 调用arp_out()将封装后的IP头部和数据发送出去
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    static uint16_t ip_id = 0;
    // 检查数据报包长是否大于IP协议最大负载包长（1500-20）
    // 如果没有超过，则直接调用ip_fragment_out()函数发送出去
    if (buf->len <= 1480)
    {
        ip_fragment_out(buf, ip, protocol, ip_id, 0, 0);
        ip_id++;
        return;
    }

    // 如果超过，则分片发送
    uint16_t len_offset = 0;
    buf_t buf_piece;
    while (buf->len > 1480)
    {
        // 首先调用buf_init()初始化一个ip_buf,将数据报包长截断
        buf_init(&buf_piece, 1480);
        memcpy(buf_piece.data, buf->data, 1480);
        // 调用ip_fragment_out()函数发送出去
        // 非最后一个分片，MF = 1
        ip_fragment_out(&buf_piece, ip, protocol, ip_id, len_offset / IP_HDR_OFFSET_PER_BYTE, 1);
        buf_remove_header(buf, 1480);
        len_offset += 1480;
    }
    // 最后一个分片
    if (buf->len)
    {
        // 首先调用buf_init()初始化一个ip_buf,将数据报包长截断
        buf_init(&buf_piece, buf->len);
        memcpy(buf_piece.data, buf->data, buf->len);
        // 调用ip_fragment_out()函数发送出去
        // 注意，最后一个分片的MF = 0
        ip_fragment_out(&buf_piece, ip, protocol, ip_id, len_offset / IP_HDR_OFFSET_PER_BYTE, 0);
        ip_id++;
    }
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}