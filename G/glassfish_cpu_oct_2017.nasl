#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103962);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2016-3092",
    "CVE-2017-10385",
    "CVE-2017-10391",
    "CVE-2017-10393",
    "CVE-2017-10400"
  );
  script_bugtraq_id(
    91453,
    101347,
    101360,
    101364,
    101383
  );

  script_name(english:"Oracle GlassFish Server 3.0.1.x < 3.0.1.17 / 3.1.2.x < 3.1.2.18 (October 2017 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle GlassFish Server
running on the remote host is 3.0.1.x prior to 3.0.1.17 or
3.1.2.x prior to 3.1.2.18. It is, therefore, affected by multiple
vulnerabilities, including multiple denial of service vulnerabilities
and unauthorized access to sensitive data.");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2017-3236626.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e07fa0e");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3937099.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e9f2a38");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GlassFish Server version 3.0.1.17 / 3.1.2.18 or later as
referenced in the October 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10391");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('audit.inc');
include('glassfish.inc');

#
# Main
#

# Check for GlassFish
get_kb_item_or_exit('www/glassfish');

port = get_glassfish_port(default:8080);

# Get the version number out of the KB.
ver = get_kb_item_or_exit('www/' + port + '/glassfish/version');
banner = get_kb_item_or_exit('www/' + port + '/glassfish/source');
pristine = get_kb_item_or_exit('www/' + port + '/glassfish/version/pristine');

# Set appropriate fixed versions.
if (ver =~ "^3\.0\.1") 
{
  min = '3.0.1';
  fix = '3.0.1.17';
}
if (ver =~ "^3\.1\.2")
{
  min = '3.1.2';
  fix = '3.1.2.18';
}

if (!empty_or_null(ver) && ver_compare(minver:min, ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + pristine +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, 'Oracle GlassFish', port, pristine);
