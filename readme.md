# InStun

## 简述

STUN(Session Traversal Utilities for NAT，NAT会话穿越应用程序)用于穿透内网
的一种工具，被ICE、VOIP、WebRTC等大量使用。然而支持RFC5389和RFC5780的STUN服
务器，需要架设在拥有两个IP的公网主机中，对于国内大多数云服务器只提供一个IP地址
的情况下，使用两台云主机来实现原来一台主机拥有2个IP地址来实现的功能是本项目的
目标。

## 检测NAT行为

### 检测连通性

```
Client ---Bind Request--> Server
```

### 检测NAT映射行为

```
Test1:

    Client ---Binding Request-----> Server(primary ip and port)

    Client <--Binding Response----- Server(primary ip and port)
           <--Xor-Mapped-Address---
           <--Other-Address--------
            (alternate ip and port)

    Client: 如果返回的IP地址和端口与自己发送socket的相同，说明不在NAT后，退出

Test2:

    Clinet ---Binding Request-----> Server(alternate ip and primary port)

    Client <--Binding Response----- Server(alternate ip and primary port)
           <--Xor-Mapped-Address---

    Client: 如果返回的IP地址和端口号与Test1相同，NAT映射与对端无关，退出

Test3:

    Client ---Binding Request-----> Server(alternate ip and port)

    Clinet <--Binding Response----> Server(alternate ip and port)
           <--Xor-Mapped-Address---

    Client: 如果返回的IP地址和端口号与Test2相同，NAT映射仅与对端IP有关，退出

    NAT映射与对端IP和端口都有关，退出
```

### 检测NAT过滤行为

```
Test1:

    Client ---Binding Request-----> Server(primary ip and port)

    Client <--Binding Response----- Server(primary ip and port)
           <--Xor-Mapped-Address---
           <--Other-Address--------
            (alternate ip and port)

Test2:

    Client ---Binding Request-----> Server(primary ip and port)
           ---Change-Requesr------>
             (change ip and port)

    Client <--Binding Rsponse------ Server(alternate ip and port)

    Client: 如果收到，NAT过滤与对端无关，退出

Test3:

    Client ---Binding Request-----> Server(primary ip and port)
                 (change port)

    Client <--Binding Response----- Server(primary ip and alternate port)

    Clinet: 如果收到，NAT过滤仅与对端IP有关，退出

    NAT过滤与对端IP和端口都有关，退出
```

## 支持进度

- [x] BINDING_REQUEST

- [x] BINDING_RESPONSE

- [x] XOR-MAPPED-ADDRESS

- [x] MAPPED-ADDRESS

- [x] CHANGE-REQUEST

- [x] OTHER_ADDRESS

## 使用示例

[参阅这里](example/udp.go)

