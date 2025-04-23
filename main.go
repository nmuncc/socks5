package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

const cmdBind = 0x01
const atypIPV4 = 0x01
const atypeHOST = 0x03
const atypeIPV6 = 0x04

// Authentication METHODs described in RFC 1928, section 3.
const (
	noAuthRequired   byte = 0
	passwordAuth     byte = 2
	noAcceptableAuth byte = 255
)

// passwordAuthVersion is the auth version byte described in RFC 1929.
const passwordAuthVersion = 1

// socks5Version is the byte that represents the SOCKS version
// in requests.
const socks5Version byte = 5

var lastLoadedTime time.Time
var specailIPs []string
var allowedIPs []string

func updateSpecailIPs(reader *bufio.Reader, conn net.Conn) bool {
	peekData, err := reader.Peek(3)
	if err != nil {
		return false
	}
	if !strings.HasPrefix(string(peekData), "GET") {
		return false
	}

	// 使用 http.Request 对象解析连接的请求
	request, err := http.ReadRequest(reader)
	if err != nil {
		fmt.Println("Error reading request:", err)
		return false
	}

	// 获取请求头信息
	header := request.Header

	// 输出请求头信息
	fmt.Println("Request Headers:")
	for key, values := range header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", key, value)
			if key == "Add_remote_ip" && value == os.Getenv("TOKEN") {
				remoteIp := strings.Split(conn.RemoteAddr().String(), ":")[0]
				specailIPs = append(specailIPs, remoteIp)
				updateIps()
				log.Printf("client %v update specailIPs", remoteIp)
				return true
			}
		}
	}
	return false
}

func updateIps() {
	// 获取 ALLOWED_IPS 环境变量的值
	allowedIPsString := os.Getenv("ALLOWED_IPS")
	// 将字符串以逗号分隔为切片
	// 定义允许连接的 IP 地址
	allowedIPs = strings.Split(allowedIPsString, ",")
	allowedIPs = append(allowedIPs, specailIPs...)
	log.Printf("allowedIPs: %v", allowedIPs)
}

func init() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
	updateIps()
	lastLoadedTime = time.Now()
}

func checkEnv() {
	// 检查环境变量文件的修改时间
	fileInfo, err := os.Stat(".env")
	if err != nil {
		fmt.Println("Failed to check environment variables file:", err)
		return
	}

	// 检查文件的修改时间与上次加载的时间是否一致
	if fileInfo.ModTime().After(lastLoadedTime) {
		// 加载新的环境变量文件
		err = godotenv.Overload(".env")
		if err != nil {
			fmt.Println("Failed to reload environment variables:", err)
			return
		}
		updateIps()
		// 更新最后加载时间
		lastLoadedTime = time.Now()

		// 执行环境变量更新后的操作（如重启服务器等）
		fmt.Println("Environment variables reloaded")
	}
}

func main() {
	server, err := net.Listen("tcp", "0.0.0.0:"+os.Getenv("PORT"))
	if err != nil {
		panic(err)
	}
	defer server.Close()
	log.Println("Server started. Listening on :" + os.Getenv("PORT"))

	for {
		conn, err := server.Accept()
		if err != nil {
			log.Printf("Accept failed %v", err)
			continue
		}

		checkEnv()
		go process(conn)
	}
}

func needAuth(conn net.Conn) bool {
	// 获取客户端的 IP 地址
	clientIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
	// 检查客户端 IP 是否在白名单中
	allowed := false
	for _, ip := range allowedIPs {
		if ip == clientIP {
			allowed = true
			break
		}
	}

	// 如果客户端 IP 不在白名单中，需要认证
	if !allowed {
		// log.Println("Connection from", clientIP, "is not allowed")
		return true
	}

	// 处理客户端连接
	log.Println("Connection from", clientIP, "is allowed")
	return false
}

func sendHTTPResponse(conn net.Conn, statusCode int, body string) {
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\n\r\n%s", statusCode, http.StatusText(statusCode), len(body), body)
	conn.Write([]byte(response))
}

func process(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if needAuth(conn) && updateSpecailIPs(reader, conn) {
		sendHTTPResponse(conn, http.StatusOK, "set ip success")
		return
	}
	err := auth(reader, conn)
	if err != nil {
		log.Printf("client %v auth failed:%v", conn.RemoteAddr(), err)
		return
	}
	err = connect(reader, conn)
	if err != nil {
		log.Printf("client %v auth failed:%v", conn.RemoteAddr(), err)
		return
	}
}

func auth(reader *bufio.Reader, conn net.Conn) (err error) {
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	// VER: 协议版本，socks5为0x05
	// NMETHODS: 支持认证的方法数量
	// METHODS: 对应NMETHODS，NMETHODS的值为多少，METHODS就有多少个字节。RFC预定义了一些值的含义，内容如下:
	// X’00’ NO AUTHENTICATION REQUIRED
	// X’02’ USERNAME/PASSWORD
	ver, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("read ver failed:%w", err)
	}
	if ver != socks5Version {
		return fmt.Errorf("not supported ver:%v", ver)
	}
	methodSize, err := reader.ReadByte()
	if err != nil {
		return fmt.Errorf("read methodSize failed:%w", err)
	}
	method := make([]byte, methodSize)
	_, err = io.ReadFull(reader, method)
	if err != nil {
		return fmt.Errorf("read method failed:%w", err)
	}

	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	authMethod := noAuthRequired
	if needAuth(conn) { // 不在白名单的需要认证
		if method[0] == noAuthRequired { // 客户端没有支持认证，报错
			conn.Write([]byte{socks5Version, noAcceptableAuth})
			return fmt.Errorf("no acceptable auth")
		}
		authMethod = passwordAuth
	}
	_, err = conn.Write([]byte{socks5Version, authMethod})
	if err != nil {
		return fmt.Errorf("write failed:%w", err)
	}

	if authMethod == noAuthRequired {
		return nil
	}

	// +----+--------+
	// |VER | STATUS |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	hdr := make([]byte, 2)
	_, err = io.ReadFull(reader, hdr)
	if err != nil {
		return fmt.Errorf("read auth packet header failed:%w", err)
	}
	if hdr[0] != passwordAuthVersion {
		return fmt.Errorf("bad SOCKS auth version")
	}

	usrLen := int(hdr[1])
	usrBytes := make([]byte, usrLen)
	if _, err := io.ReadFull(reader, usrBytes); err != nil {
		return fmt.Errorf("could not read auth packet username")
	}
	var hdrPwd [1]byte
	if _, err := io.ReadFull(reader, hdrPwd[:]); err != nil {
		return fmt.Errorf("could not read auth packet password length")
	}
	pwdLen := int(hdrPwd[0])
	pwdBytes := make([]byte, pwdLen)
	if _, err := io.ReadFull(reader, pwdBytes); err != nil {
		return fmt.Errorf("could not read auth packet password")
	}

	if string(usrBytes) != os.Getenv("USER_NAME") || string(pwdBytes) != os.Getenv("PASSWD") {
		conn.Write([]byte{1, 1}) // auth error
		return fmt.Errorf("error username or password")
	}
	conn.Write([]byte{1, 0}) // auth success

	return nil
}

func connect(reader *bufio.Reader, conn net.Conn) (err error) {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// VER 版本号，socks5的值为0x05
	// CMD 0x01表示CONNECT请求
	// RSV 保留字段，值为0x00
	// ATYP 目标地址类型，DST.ADDR的数据对应这个字段的类型。
	//   0x01表示IPv4地址，DST.ADDR为4个字节
	//   0x03表示域名，DST.ADDR是一个可变长度的域名
	// DST.ADDR 一个可变长度的值
	// DST.PORT 目标端口，固定2个字节

	buf := make([]byte, 4)
	_, err = io.ReadFull(reader, buf)
	if err != nil {
		return fmt.Errorf("read header failed:%w", err)
	}
	ver, cmd, atyp := buf[0], buf[1], buf[3]
	if ver != socks5Version {
		return fmt.Errorf("not supported ver:%v", ver)
	}
	if cmd != cmdBind {
		return fmt.Errorf("not supported cmd:%v", ver)
	}
	addr := ""
	switch atyp {
	case atypIPV4:
		_, err = io.ReadFull(reader, buf)
		if err != nil {
			return fmt.Errorf("read atyp failed:%w", err)
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])
	case atypeHOST:
		hostSize, err := reader.ReadByte()
		if err != nil {
			return fmt.Errorf("read hostSize failed:%w", err)
		}
		host := make([]byte, hostSize)
		_, err = io.ReadFull(reader, host)
		if err != nil {
			return fmt.Errorf("read host failed:%w", err)
		}
		addr = string(host)
	case atypeIPV6:
		return errors.New("IPv6: no supported yet")
	default:
		return errors.New("invalid atyp")
	}
	_, err = io.ReadFull(reader, buf[:2])
	if err != nil {
		return fmt.Errorf("read port failed:%w", err)
	}
	port := binary.BigEndian.Uint16(buf[:2])

	dest, err := net.Dial("tcp", fmt.Sprintf("%v:%v", addr, port))
	if err != nil {
		return fmt.Errorf("dial dst failed:%w", err)
	}
	defer dest.Close()
	log.Println("dial", addr, port)

	// +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	// VER socks版本，这里为0x05
	// REP Relay field,内容取值如下 X’00’ succeeded
	// RSV 保留字段
	// ATYPE 地址类型
	// BND.ADDR 服务绑定的地址
	// BND.PORT 服务绑定的端口DST.PORT
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_, _ = io.Copy(dest, reader)
		cancel()
	}()
	go func() {
		_, _ = io.Copy(conn, dest)
		cancel()
	}()

	<-ctx.Done()
	return nil
}
