#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77987);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-3338");
  script_bugtraq_id(69176);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum95491");

  script_name(english:"Cisco Unified Communications Manager 'CTIManager' Remote Command Execution (CSCum95491)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an arbitrary command execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Unified
Communications Manager (CUCM) device has a flaw in the 'CTIManager'
module that allows a remote, authenticated attacker to execute
arbitrary commands with elevated privileges by using a specially
crafted SSO token.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=35258
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?489ea93b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a fixed CUCM version listed in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3338");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Cisco CTI Manager AND Single Sign On must be enabled
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver         = get_kb_item_or_exit("Host/Cisco/CUCM/Version");
ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");
fixed_ver = NULL;

app_name  = "Cisco Unified Communications Manager (CUCM)";

if (ver =~ "^10\.0\." && ver_compare(ver:ver, fix:"10.0.1.13009.1", strict:FALSE) < 0)
  fixed_ver = "10.0.1.13009-1";  

if(isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

report =
  '\n  Cisco bug ID      : CSCum95491'     +
  '\n  Installed release : ' + ver_display +
  '\n  Fixed release     : ' + fixed_ver   +
  '\n';

security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
