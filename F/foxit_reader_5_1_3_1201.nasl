#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57050);
  script_version("1.7");
  script_cvs_date("Date: 2018/08/07 16:46:51");

  script_bugtraq_id(50947);

  script_name(english:"Foxit Reader < 5.1.3.1201 Memory Corruption RCE");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote host is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description",  value:
"The version of Foxit Reader installed on the remote Windows host is
prior to 5.1.3.1201. It is, therefore, affected by a memory corruption
issue due to a cross-border assignment of an array when opening a
specially crafted PDF file. An attacker can exploit this, by tricking
a user into opening a crafted PDF file, to execute arbitrary code with
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/company/press.php?id=235");
  script_set_attribute(attribute:"solution",  value:
"Upgrade to Foxit Reader version 5.1.3.1201 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Foxit Reader";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install["version"];
path    = install["path"];

report = NULL;

fixed_version = "5.1.3.1201";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port)
    port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version + '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
