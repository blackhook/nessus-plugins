#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79668);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-3366");
  script_bugtraq_id(70855);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup88089");

  script_name(english:"Cisco Unified Communications Manager Unspecified SQL Injection (CSCup88089)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unified Communications Manager installed on the
remote host is affected by an unspecified SQL injection vulnerability
due to a failure to properly sanitize user-supplied input in the
administrative web interface. This allows an authenticated, remote
attacker to obtain information that the affected application can
access.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=36293");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=36293
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d80f3d5f");
  script_set_attribute(attribute:"solution", value:
"Contact vendor for remediation details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3366");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver_display = get_kb_item_or_exit("Host/Cisco/CUCM/Version_Display");
app_name    = "Cisco Unified Communications Manager (CUCM)";

# Affected version listed: 9.1(2.10000.28) Base
# Format version expected: 9.1.2.1000-28
if (ver_display != "9.1.2.10000-28") audit(AUDIT_INST_VER_NOT_VULN, app_name, ver_display);

set_kb_item(name:'www/0/SQLInjection', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug ID   : CSCup88089' +
    '\n  System version : ' + ver_display +
    '\n';
  security_warning(port:0, extra:report);
}
else security_warning(0);
