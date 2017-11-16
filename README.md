# Keyless solution
The solution of keyless proxy.

## The traditional proxy for SSL
SSL is widely used these years to provide secure communication links between clients and servers.
Usually, to provide proxy service for these organizations' source servers, the proxy server has to keep the organizations' private keys.
When a client is requesting the proxy server, the proxy server uses the private key to initialize a SSL link with the client as if it is the source server.

Since the proxy provider is usually a CDN (Content Delivery Network) company, there will be a security issue when distributing the private keys among the proxy servers.

## The keyless proxy
Some organizations demand a higher secure level and won't trust the  private keys to others.
To provide proxy service to these organizations, CDN companies could use the keyless proxy.
These organizations needn't share the private key with CDN companies.
Instead, they have to distribute some keyless servers to provide keyless service for the usage of CDN companies.

When a client is requesting a proxy server, the server will try to initialize a SSL link with the client.
During the SSL handshaking, some data needs to be processed with the private key.
The proxy server will send these data to a keyless server, and the keyless server will use the private key to manipulate the data and respond with the outcome.
The proxy server will complete the SSL handshaking with the outcome as if it is the source server.

This project is aimed to provide a demo solution for the keyless proxy, which is well-explained in the [technical blog][1].

## Components
To realize keyless proxy, there will be three components needed as follow:

* Keyless Server, which is used to provide the keyless service. CloudFlare has published the source code of the keyless server in `C` and `Go`.
* Proxy Server, which will request the keyless service and complete the SSL handshaking. Since a lot of companies use `Nginx + lua` as their business layer, I will modify the Nginx as the proxy server.
* OpenSSL support, which will break down the SSL handshaking and wait the proxy server for the data processed by private key. To break down the SSL handshaking,
OpenSSL needs some modification.

## Keyless server
The main problem about the source code published by CloudFlare is the certificates used for test is out of date, thus causing the failure during testing. I have renewed the certificates in the `keyless-server\testing` directory.

For more information about how to generate certificates with OpenSSL, please visit [OpenSSL Command-Line HOWTO][3] and [OpenSSL Command Line Utilities][4].

## Note
The first version of the project is not finished yet.
Since it's a part-time entertainment for me, I couldn't guarantee the develop progress.
But I have realized it once before, so it should be soon.

## Contact
Feel free to contact me via [e-mail][2] if you have any questions.

[1]: https://blog.cloudflare.com/keyless-ssl-the-nitty-gritty-technical-details/
[2]: mailto:suntobright@gmail.com
[3]: https://www.madboa.com/geek/openssl/
[4]: https://wiki.openssl.org/index.php/Command_Line_Utilities
