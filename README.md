# Legal Disclaimer
This script is an example script and is not supported under any Zerto support program or service. The author and Zerto further disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.

In no event shall Zerto, its authors or anyone else involved in the creation, production or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or the inability to use the sample scripts or documentation, even if the author or Zerto has been advised of the possibility of such damages. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.

# Send-ZVMSyslog
This script is designed to query the Zerto ZVM Alerts API to pull the relevant alerts and send those alerts to a Syslog server of the users choosing. 

Leveraging the Zerto Rest API the script with authenticate with the ZVM to pull the alerts from the relevant site. Once the alerts are collected the script will send the alerts to a Syslog server
that the user has configured in the script variables below. At the end of the script the API session will be closed, as the script is intended to be run as a Task or via orchestration every few minutes.

To run this script the computer executing the script must have the Posh-Syslog module installed before running the script. For more information 
please review the module in the PowerShell Gallery (https://www.powershellgallery.com/packages/Posh-SYSLOG/3.3). 

It is important to note which protocol (TCP / UDP) and what default port the Syslog application listens on. By default Syslog protocol uses UDP and port 514, but some Syslog Server
applications do not share these same defaults.

# Prerequisites
This script is required to be run as Administrator

# Environment Requirements 
- PowerShell 5.1+
- Posh-Syslog Module

In Script Variables
- ZVM IP 
- ZVM User 
- ZVM Password
- Book Mark File location
- Syslog Server IP 
- Syslog Protocol (UDP, TCP, TCPwithTLS) 
- Syslog Port 

# Running Script
Once the necessary configuration requirements have been completed the script can be run one time or as a scheduled task on the script host 
