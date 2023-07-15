#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89690);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1297");
  script_bugtraq_id(83390);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul84801");
  script_xref(name:"IAVA", value:"2016-A-0057");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160224-ace");

  script_name(english:"Cisco ACE 4710 Device Manager GUI Remote Command Injection Vulnerability (cisco-sa-20160224-ace)");
  script_summary(english:"Checks the ACE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco Application Control Engine (ACE) software installed on the
remote Cisco ACE 4710 device is an A5 version prior to A5(3.0). It is,
therefore, affected by a remote command injection vulnerability in the
device manager GUI due to improper validation of user-supplied input
in HTTP POST requests. An authenticated, remote attacker can exploit
this to bypass the role-based access control (RBAC) restrictions and
execute CLI commands with 'admin' privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160224-ace
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6bd62857");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul84801");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco ACE version A5(3.1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1297");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_control_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ace_version.nasl");
  script_require_keys("Host/Cisco/ACE/Version", "Host/Cisco/ACE/Model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/Cisco/ACE/Version");
model   = get_kb_item_or_exit("Host/Cisco/ACE/Model");

if (model != "4710") audit(AUDIT_DEVICE_NOT_VULN, "ACE " + model);

if (report_paranoia < 2) audit(AUDIT_PARANOID); # A workaround is available

if (
  version =~ "^A5\([0-2][^0-9]" ||
  version =~ "^A5\(3(\.0)?\)"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : A5(3.1)' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ACE", version);
