# oauth2-client-for-chrome-extensions

Chrome 拡張で下記のフローを実行するためのOAuth 2.0クライアント（実験用）

[ウェブサーバー アプリケーションに OAuth 2\.0 を使用する  \|  Authorization  \|  Google Developers](https://developers.google.com/identity/protocols/oauth2/web-server?hl=ja)

## 必要環境

- Go 1.26.0 以上
- Redis（localhost:6379）

Echo v5 と echo-contrib/v5 を使用しています。

```sh
go test ./...
go build .
```
