# 更新说明
## 1.1 2024-12-02
**以80端口示例**

IPTABLES: `iptables -t mangle -A OUTPUT -p tcp --sport 80 -m tcp --tcp-flags SYN,ACK,ACK SYN,ACK -j NFQUEUE --queue-num 100`

python脚本: `python3 geneva.py -q 100 -w 1 -s 7 -c 7 -n 7`

参数说明:
* -q: iptables标记
* -w: window_size 最小分片尺寸（单位：字节）
* -s: window_scale 调整混淆包的window_scale,倍率为2的n次方
* -c: confusion_times 调整混淆包的发送次数，虽然不知道有啥用，但是确实多发几个过移动效果更好些，当然，随之而来的是更高的带宽与延迟开销
* -n: split_number 数据包分片数量（一个请求的最多分片次数，达到此阈值的包不再分片）

## 1.0 2024-11-29
Useage: `python3 geneva2.py -q 100 -w 1 -s 7 -c 7`

1. -w: window_size
2. -s: window_scale 
3. -c: 混淆次数，建议7次，减少此值可提速（0最快）
