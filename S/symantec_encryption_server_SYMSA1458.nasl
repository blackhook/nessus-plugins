#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112155);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-5243");
  script_bugtraq_id(105062);
  script_xref(name:"IAVB", value:"2018-B-0113");

  script_name(english:"Symantec Encryption Management Server < 3.4.2 MP1 Denial of Service Vulnerability (SYMSA1458)");

  script_set_attribute(attribute:"synopsis", value:
"A security policy management application running on the remote host is
affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Encryption Management Server running on the
remote host is prior to version 3.4.2 MP1. It is, therefore,
affected by an unspecified denial of service vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://support.symantec.com/en_US/article.SYMSA1458.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Encryption Management Server version 3.4.2 MP1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5243");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:encryption_management_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_encryption_server_detect.nbin");
  script_require_keys("LDAP/symantec_encryption_server/detected");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Symantec Encryption Management Server";

get_kb_item_or_exit("LDAP/symantec_encryption_server/detected");

port = get_service(svc:"ldap", default: 389, exit_on_fail:FALSE);

version = get_kb_item_or_exit("LDAP/symantec_encryption_server/" + port + "/version");
build = get_kb_item_or_exit("LDAP/symantec_encryption_server/" + port + "/build");

# Detection plugin places "Unknown" value if it
# happens to fail when looking for build or version
# Note: Even base versions still should have
#       build information associated with them.
if (version =~ "^U|unknown$" || build =~ "^U|unknown$")
  audit(AUDIT_UNKNOWN_APP_VER, app_name);

# Complete the version by appending build number
version = version + '.' + build;

# Check for granularity in this full version number
if (version !~ "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, version);

fix = "3.4.2.353";
fix_disp = "3.4.2.353 (3.4.2 MP1)";

if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_disp +
    '\n';
  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
