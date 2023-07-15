#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if ( !defined_func("nasl_level") || nasl_level() < 5200 ) exit(0, "Not Nessus 5.2+");

if (description)
{
  script_id(92365);
  script_version("1.10");
  script_cvs_date("Date: 2020/01/27");

  script_name(english:"Microsoft Windows Hosts File");
  script_summary(english:"Collect host file from machine.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to collect the hosts file from the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to collect the hosts file from the remote Windows host
and report it as attachment.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"hardware_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("data_protection.inc");

# Disable if data protection is filtering ip addresses
data_protection::disable_plugin_if_set(flags:[data_protection::DPKB_IPADDR]);

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if (!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"ADMIN$");

if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"ADMIN$");
}

attachments = make_list();
content = '';
fh = CreateFile(
    file               : 'System32\\drivers\\etc\\hosts',
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
);

if (!isnull(fh))
{
  off = 0;
  repeat
  {
    data = ReadFile(handle:fh, length:4096, offset:off);
    content += data;
    len = strlen(data);
    off += len;
  }
  until (len < 4096 || off > 100*1024*1024); # limit to 100 MB
  CloseFile(handle:fh);

  attachments[0] = make_array();
  attachments[0]["name"] = "hosts";
  attachments[0]["value"] = content;
  attachments[0]["type"] = "text/plain";
}

NetUseDel();

if (max_index(attachments) > 0)
{
  report = 'Windows hosts file attached.\n\n';
  sha1 = hexstr(SHA1(content));
  md5 = hexstr(MD5(content));
  sha2 = hexstr(SHA256(content));

  report += 'MD5: ' + md5 + '\n';
  report += 'SHA-1: ' + sha1 + '\n';
  report += 'SHA-256: ' + sha2;

  security_report_with_attachments(port:0, level:0, extra:report, attachments:attachments);
}
else
{
  exit(0, "%SYSTEMROOT%\System32\drivers\etc\hosts not found.");
}
