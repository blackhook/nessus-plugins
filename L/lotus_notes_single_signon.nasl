#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66722);
  script_version("1.6");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2013-0522");
  script_bugtraq_id(59809);

  script_name(english:"IBM Notes Single Sign On Password Disclosure");
  script_summary(english:"Checks if Single Sign On is installed and used");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Notes installed on the remote Windows host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Notes installed on the remote Windows host uses the
built-in Single Sign On feature for authentication.  Single Sign On is
affected by a vulnerability wherein malicious code planted on a user's
workstation can be used to reveal the password of an authenticated
user.");
  # https://www.ibm.com/blogs/psirt/security-bulletin-for-safer-ibm-notes-single-sign-on-with-windows-use-notes-shared-login-or-notes-federated-login-cve-2013-0522/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cc61129");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21634508");
  script_set_attribute(attribute:"solution", value:
"Disable Notes Client Single Sign On.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0522");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lotus_notes_installed.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Lotus_Notes/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "IBM Lotus Notes";
kb_base = "SMB/Lotus_Notes/";

port = get_kb_item_or_exit('SMB/transport');
version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');
ver_ui = get_kb_item_or_exit(kb_base + 'Version_UI');

ver = split(version, sep:'.');
if (version =~ '^(8\\.(0\\.|5\\.[0-3])|9\\.0)')
{
  if (int(ver[0]) >= 9)
  {
    status = get_kb_item_or_exit('SMB/svc/IBM Notes Single Logon');
    if (status != SERVICE_ACTIVE)
      exit(0, 'The IBM Notes Single Logon service is installed but not active.');
  }
  else
  {
    status = get_kb_item_or_exit('SMB/svc/Lotus Notes Single Logon');
    if (status != SERVICE_ACTIVE)
      exit(0, 'The Lotus Notes Single Logon service is installed but not active.');
  }

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
