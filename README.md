# Laravel Client Certificate Middleware

This middleware provides user authentication (and registration on initial request) via HTTPS client certificate. It is assumed the web server validates the authenticity of the certificate, and that it provides the CN from the certificate in the `$_SERVER['SSL_CLIENT_S_CN']` PHP variable.
