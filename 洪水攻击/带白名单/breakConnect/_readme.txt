
使用：
1、运行前先打开无线网卡的监听模式
2、在breakConnect目录下编译：make
3、若不使用白名单	
   执行：需要root权限，格式为“路径/breakConnect 监听模式的网卡 源地址 目的地址”

4、若需要使用白名单，在白名单文件white.txt中写入终端和ap的mac地址，一行一个。
   执行：需要root权限，格式为“路径/breakConnect 监听模式的网卡 源地址 -w white.txt”

5、开始攻击后 按ctrl+Z结束退出



