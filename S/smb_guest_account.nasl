#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
 script_id(26919);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/21");

 script_cve_id("CVE-1999-0505");

 script_name(english:"Microsoft Windows SMB Guest Account Local User Access");
 script_summary(english:"Attempts to log into the remote host");

 script_set_attribute(attribute:"synopsis", value:"It is possible to log into the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running one of the Microsoft Windows operating
systems or the SAMBA daemon. It was possible to log into it as a guest
user using a random account.");
 script_set_attribute(attribute:"solution", value:
"In the group policy change the setting for 'Network access: Sharing
and security model for local accounts' from 'Guest only - local users
authenticate as Guest' to 'Classic - local users authenticate as
themselves'. Disable the Guest account if applicable.

If the SAMBA daemon is running, double-check the SAMBA configuration
around guest user access and disable guest access if appropriate");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0505");
 script_set_attribute(attribute:"cvss_score_rationale", value:"AV:N is justified since the plugin tries to login via network services. NIST specifies that the vulnerability pertains to a domain user. Given that the plugin only tests for a guest account, which likely has limited permissions, the CIA is partial instead of complete.");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows Authenticated Powershell Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"1999/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/04");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Windows");

 script_dependencies("smb_login.nasl");
 script_require_keys("SMB/guest_enabled");
 exit(0);
}

#

include('smb_func.inc');

val = get_kb_item("SMB/guest_enabled");

if (val)
  security_hole(kb_smb_transport());
