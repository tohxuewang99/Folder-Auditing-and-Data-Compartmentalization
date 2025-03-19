Overview
This PowerShell script audits folder permissions and generates detailed CSV reports. It supports cross-platform environments (Windows, Linux, macOS) and integrates with LDAP and SMTP for enhanced functionality.

Features
Audits folder permissions for specified paths.

Generates CSV reports with detailed permission information.

Supports LDAP for AD account enrichment.

Sends email reports via SMTP.

Cross-platform compatibility.

Usage
Basic Usage
Run the script with a single folder path:

powershell
Copy
.\audit.ps1 -Path "D:\SharedFolder" -OutputPath "D:\Reports"
This audits D:\SharedFolder and saves the report to D:\Reports.

Using a CSV Input
Provide a CSV file containing multiple folder paths:

powershell
Copy
.\audit.ps1 -CsvPaths "D:\PathsToAudit.csv" -OutputPath "D:\Reports"
The CSV file should have the schema: Path, FolderLevel, Exclude.

Advanced Configuration
Use a JSON configuration file to enable LDAP and SMTP:

powershell
Copy
.\audit.ps1 -Path "D:\SharedFolder" -OutputPath "D:\Reports" -ConfigFile "config.json"
Example config.json:

json
Copy
{
  "EnableLdap": true,
  "GCServer": "ldap.example.com",
  "GCPort": 389,
  "GCUser": "admin",
  "GCPassword": "password",
  "GCBaseDN": "dc=example,dc=com",
  "EnableEmail": true,
  "SmtpServer": "smtp.example.com",
  "SmtpPort": 587,
  "SmtpUser": "user@example.com",
  "SmtpPassword": "password",
  "EmailFrom": "audit@example.com",
  "EmailTo": "admin@example.com",
  "EmailSubject": "Folder Security Audit Report"
}
Excluding Inherited Permissions
Use the -DropInheritance switch to exclude folders with inherited permissions:

powershell
Copy
.\audit.ps1 -Path "D:\SharedFolder" -OutputPath "D:\Reports" -DropInheritance
Auditing All Subfolders
Set -FolderLevel to 0 to audit all subfolders:

powershell
Copy
.\audit.ps1 -Path "D:\SharedFolder" -OutputPath "D:\Reports" -FolderLevel 0
Task Scheduler Automation
The provided XML file (auditor_task 2.xml) can be imported into Task Scheduler to automate script execution.

Import the Task
Save the XML file and import it into Task Scheduler:

powershell
Copy
schtasks /Create /XML "C:\path\to\auditor_task 2.xml" /TN "auditor_task"
Modify the Task
Update the Arguments field in the XML to point to the correct script path and adjust parameters as needed.

Run the Task
The task will execute automatically at the specified time or can be manually triggered.

Output
The script generates a CSV report with the following columns:

Path: The folder path being audited.

Account: The account or group with permissions.

AccessType: The type of access (e.g., Allow, Deny).

Rights: The specific permissions (e.g., Read, Write).

Inherited: Whether the permission is inherited.

AccountType: The type of account (e.g., ADAccount, LocalAccount).

Enabled: Whether the AD account is enabled (if LDAP is enabled).

AccountExpires: The expiration date of the AD account (if LDAP is enabled).

Requirements
PowerShell 7.0+

LDAP server (optional)

SMTP server (optional)

Example CSV Report
csv
Copy
Path,Account,AccessType,Rights,Inherited,AccountType,Enabled,AccountExpires
D:\SharedFolder,Administrator,Allow,Full Control,False,ADAccount,True,2025-12-31
D:\SharedFolder\SubFolder,Everyone,Allow,Read,True,BuiltIn,,,
Troubleshooting
Ensure the script has the necessary permissions to access the folders being audited.

Verify that the LDAP and SMTP configurations are correct if using advanced features.

Check the Task Scheduler logs for any errors during automated execution.

License
This project is licensed under the MIT License. See the LICENSE file for details.
