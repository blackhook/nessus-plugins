#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74430);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2014-0531",
    "CVE-2014-0532",
    "CVE-2014-0533",
    "CVE-2014-0534",
    "CVE-2014-0535",
    "CVE-2014-0536"
  );
  script_bugtraq_id(
    67961,
    67962,
    67963,
    67970,
    67973,
    67974
  );

  script_name(english:"Adobe AIR <= AIR 13.0.0.111 Multiple Vulnerabilities (APSB14-16)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Adobe AIR on the remote
Windows host is equal or prior to 13.0.0.111. It is, therefore,
affected by the following vulnerabilities :

  - Multiple, unspecified errors exist that could allow
    cross-site scripting attacks. (CVE-2014-0531,
    CVE-2014-0532, CVE-2014-0533)

  - Multiple, unspecified errors exist that could allow
    unspecified security bypass attacks. (CVE-2014-0534,
    CVE-2014-0535)

  - An unspecified memory corruption issue exists that
    could allow arbitrary code execution. (CVE-2014-0536)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb14-16.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR 14.0.0.110 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0536");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_air_installed.nasl");
  script_require_keys("SMB/Adobe_AIR/Version", "SMB/Adobe_AIR/Path");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Adobe_AIR/Version");
path = get_kb_item_or_exit("SMB/Adobe_AIR/Path");

version_ui = get_kb_item("SMB/Adobe_AIR/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui + ' (' + version + ')';

cutoff_version = '13.0.0.111';
fix = '14.0.0.110';
fix_ui = '14.0';

if (ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
