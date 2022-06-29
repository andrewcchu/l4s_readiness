from scapy.all import *

sites =  ["live.com" ,"taobao.com" ,"msn.com" ,"sina.com.cn" ,"yahoo.co.jp" ,"google.co.jp" ,"linkedin.com" ,"weibo.com" ,"bing.com" ,"yandex.ru" ,"vk.com"]
# sites =  ["yandex.ru" ,"linkedin.com", "reddit.com"]
res, unans = traceroute(sites,dport=80,maxttl=20,retry=-2)
print(res)
res.graph(target="> /Users/andrewcchu/Documents/GitHub/l4s/figs/default_multi.svg")