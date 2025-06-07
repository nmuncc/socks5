# go-socks-proxy
Go-Socks-Proxy is a simple open-source project written in Go that allows you to connect to the internet through the SOCKS5 protocol. It's ideal for deployment on internal servers since it only handles IP whitelisting and doesn't implement encryption.

## Installation
1. Download the source code and navigate to the directory.
2. Run `go build .` to compile the `go-socks-proxy` file.
3. Configure the `ALLOWED_IPS` and `PORT` variables in the `.env` file.
4. Run `nohup ./go-socks-proxy &` to start the server.

## Usage
Go-Socks-Proxy is easy to use. Simply configure your device's network settings to use the server's IP address and the port number you specified in the `.env` file.

## Security
Please note that Go-Socks-Proxy doesn't provide encryption, so it's not recommended to use it for sensitive data.

## Contributions
Thanks for contributing to the project.
[![Powered by DartNode](https://dartnode.com/branding/DN-Open-Source-sm.png)](https://dartnode.com "Powered by DartNode - Free VPS for Open Source")

## License
Go-Socks-Proxy is released under the MIT license. See `LICENSE` for more information.
