#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include("compat.inc");

if (description)
{
  script_id(128764);
  script_version("1.2");
  script_cvs_date("Date: 2019/09/24 11:01:34");

  script_cve_id("CVE-2018-0886");
  script_bugtraq_id(103265);

  script_name(english:"CredSSP Remote Code Execution Vulnerability March 2018 Security Update");
  script_summary(english:"Checks for AllowEncryptionOracle registry value.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host allows fallback to insecure versions of Credential Security
Support Provider protocol (CredSSP). It is therefore, affected by a remote code execution
vulnerability. An attacker who successfully exploited this vulnerability could relay user
credentials and use them to execute code on the target system. CredSSP is an authentication
provider which processes authentication requests for other applications; any application which
depends on CredSSP for authentication may be vulnerable to this type of attack. As an example
of how an attacker would exploit this vulnerability against Remote Desktop Protocol, the attacker
would need to run a specially crafted application and perform a man-in-the-middle attack against
a Remote Desktop Protocol session. An attacker could then install programs; view, change, or
delete data; or create new accounts with full user rights. The security update addresses the
vulnerability by correcting how Credential Security Support Provider protocol (CredSSP) validates
requests during the authentication process. To be fully protected against this vulnerability users
must enable Group Policy settings on their systems and update their Remote Desktop clients.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2018-0886
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f8ad7010");
  # https://support.microsoft.com/en-us/help/4093492/credssp-updates-for-cve-2018-0886-march-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?858298d1");
  script_set_attribute(attribute:"solution", value:
  "Apply patches and / or mitigations as described by Microsoft.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0886");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("smb_hotfixes.nasl", "os_fingerprint.nasl");
 script_require_keys("Host/OS");
 script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include('audit.inc');
include('install_func.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

os = get_kb_item_or_exit('Host/OS');
if('Windows' >!< os) audit(AUDIT_OS_NOT, 'Windows');
if('2003' >< os || 'XP' >< os) exit(0, 'Windows 2003 and Windows XP don\'t support CredSSP.');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
item = 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\CredSSP\\Parameters\\AllowEncryptionOracle';
value = get_registry_value(handle:hklm, item:item);
err = session_get_errorcode();
RegCloseKey(handle:hklm);
close_registry();

if (isnull(value))
{
  # make sure NULL was returned solely due to the data not existing in the registry
  if (err == ERROR_FILE_NOT_FOUND)
    audit(AUDIT_HOST_NOT, 'affected. Registry key \'HKLM:\\\'' + item + ' not found.');
  else
    audit(AUDIT_FN_FAIL, 'get_registry_value', 'error code ' + error_code_to_string(err));
}

if (value != '2') audit(AUDIT_OS_CONF_NOT_VULN, os);

report = '\nValue name: HKLM\\' + item;
report += '\nValue data: 2';

security_report_v4(port:kb_smb_transport(), extra:report, severity:SECURITY_HOLE);
