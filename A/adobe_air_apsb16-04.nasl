#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(88638);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2016-0964",
    "CVE-2016-0965",
    "CVE-2016-0966",
    "CVE-2016-0967",
    "CVE-2016-0968",
    "CVE-2016-0969",
    "CVE-2016-0970",
    "CVE-2016-0971",
    "CVE-2016-0972",
    "CVE-2016-0973",
    "CVE-2016-0974",
    "CVE-2016-0975",
    "CVE-2016-0976",
    "CVE-2016-0977",
    "CVE-2016-0978",
    "CVE-2016-0979",
    "CVE-2016-0980",
    "CVE-2016-0981",
    "CVE-2016-0982",
    "CVE-2016-0983",
    "CVE-2016-0984",
    "CVE-2016-0985"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Adobe AIR <= 20.0.0.233 Multiple Vulnerabilities (APSB16-04)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe AIR installed on the remote Windows host is prior
or equal to version 20.0.0.233. It is, therefore, affected by multiple
vulnerabilities :

  - A type confusion error exists that allows a remote
    attacker to execute arbitrary code. (CVE-2016-0985)

  - Multiple use-after-free errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-0973,
    CVE-2016-0974, CVE-2016-0975, CVE-2016-0982,
    CVE-2016-0983, CVE-2016-0984)

  - A heap buffer overflow condition exist that allows an 
    attacker to execute arbitrary code. (CVE-2016-0971)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2016-0964, CVE-2016-0965, CVE-2016-0966,
    CVE-2016-0967, CVE-2016-0968, CVE-2016-0969,
    CVE-2016-0970, CVE-2016-0972, CVE-2016-0976,
    CVE-2016-0977, CVE-2016-0978, CVE-2016-0979,
    CVE-2016-0980, CVE-2016-0981)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-04.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR version 20.0.0.260 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0985");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

cutoff_version = '20.0.0.233';
fix = '20.0.0.260';
fix_ui = '20.0';

if (ver_compare(ver:version, fix:cutoff_version) <= 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fix_ui + " (" + fix + ')' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Adobe AIR", version_report, path);
