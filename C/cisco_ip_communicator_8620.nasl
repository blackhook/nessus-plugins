#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69802);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id("CVE-2012-2490");
  script_bugtraq_id(54850);
  script_xref(name:"IAVB", value:"2012-B-0080");

  script_name(english:"Cisco IP Communicator Certificate Trust List Manipulation");
  script_summary(english:"Checks version of Cisco IP Communicator");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a softphone application installed that is affected
by an information modification vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco IP Communicator is 8.6(1).  Such versions are
potentially affected by a data modification vulnerability.  By
performing a Man-in-the-Middle attack, a remote, unauthenticated
attacker could replace the original Certificate Trust List with a
modified one.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=26606");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco IP Communicator 8.6(2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ip_communicator");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ip_communicator_installed.nasl");
  script_require_keys("SMB/Cisco IP Communicator/Path", "SMB/Cisco IP Communicator/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

app = 'Cisco IP Communicator';
version = get_kb_item_or_exit('SMB/Cisco IP Communicator/Version');
path = get_kb_item_or_exit('SMB/Cisco IP Communicator/Path');

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 6 && ver[2] == 1)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.6.2.0 \n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
