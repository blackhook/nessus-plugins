#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84156);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2015-0346",
    "CVE-2015-0347",
    "CVE-2015-0348",
    "CVE-2015-0349",
    "CVE-2015-0350",
    "CVE-2015-0351",
    "CVE-2015-0352",
    "CVE-2015-0353",
    "CVE-2015-0354",
    "CVE-2015-0355",
    "CVE-2015-0356",
    "CVE-2015-0357",
    "CVE-2015-0358",
    "CVE-2015-0359",
    "CVE-2015-0360",
    "CVE-2015-3038",
    "CVE-2015-3039",
    "CVE-2015-3040",
    "CVE-2015-3041",
    "CVE-2015-3042",
    "CVE-2015-3043",
    "CVE-2015-3044"
  );
  script_bugtraq_id(
    74062,
    74064,
    74065,
    74066,
    74067,
    74068,
    74069
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Adobe AIR <= 17.0.0.144 Multiple Vulnerabilities (APSB15-06)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a version of Adobe AIR installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Adobe AIR on the remote
Windows host is equal or prior to 17.0.0.144. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple double-free errors exist that allow an attacker
    to execute arbitrary code. (CVE-2015-0346,
    CVE-2015-0359)

  - Multiple memory corruption flaws exist due to improper
    validation of user-supplied input. A remote attacker can
    exploit these flaws, via specially crafted flash
    content, to corrupt memory and execute arbitrary code.
    (CVE-2015-0347, CVE-2015-0350, CVE-2015-0352,
    CVE-2015-0353, CVE-2015-0354, CVE-2015-0355,
    CVE-2015-0360, CVE-2015-3038, CVE-2015-3041,
    CVE-2015-3042, CVE-2015-3043)

  - A unspecified buffer overflow condition exists due to
    improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2015-0348)

  - Multiple unspecified use-after-free errors exist that
    allow an attacker to execute arbitrary code.
    (CVE-2015-0349, CVE-2015-0351, CVE-2015-0358,
    CVE-2015-3039)

  - An unspecified type confusion flaw exists that allows
    an attacker to execute arbitrary code. (CVE-2015-0356)

  - Multiple unspecified memory leaks exist that allows an
    attacker to bypass the Address Space Layout
    Randomization (ASLR) feature. (CVE-2015-0357,
    CVE-2015-3040)

  - An unspecified security bypass flaw exists that allows
    an attacker to disclose information. (CVE-2015-3044)");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-06.html");
  # http://helpx.adobe.com/flash-player/kb/archived-flash-player-versions.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0cb17c10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe AIR 17.0.0.172 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player domainMemory ByteArray Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

cutoff_version = '17.0.0.144';
fix = '17.0.0.172';
fix_ui = '17.0';

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
