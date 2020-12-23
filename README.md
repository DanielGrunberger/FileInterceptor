# FileInterceptor
A file interceptor script. After being the MITM, we can run it to replace any .exe file that is being downloaded using HTTP (not HTTPS).
You can also use this script with some https websites if you run sslstrip and the website is not HSTS.
You will need then to redirect traffic to the port where sslstrip is running.
