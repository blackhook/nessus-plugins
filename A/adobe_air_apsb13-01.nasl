#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63449);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2013-0630");
  script_bugtraq_id(57184);

  script_name(english:"Adobe AIR 3.x <= 3.5.0.880 Buffer Overflow (APSB13-01)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a version of Adobe AIR that is
affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version, the instance of Adobe AIR 3.x on the remote
Windows host is 3.5.0.880 or earlier.  It is, therefore, reportedly
affected by a unspecified buffer overflow vulnerability that can lead to
arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb13-01.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR 3.5.0.1060 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0630");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

cutoff_version = '3.5.0.880';
fix = '3.5.0.1060';
fix_ui = '3.5';

if (version =~ '^3\\.' && ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
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
