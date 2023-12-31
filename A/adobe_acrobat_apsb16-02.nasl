#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87917);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2016-0931",
    "CVE-2016-0932",
    "CVE-2016-0933",
    "CVE-2016-0934",
    "CVE-2016-0935",
    "CVE-2016-0936",
    "CVE-2016-0937",
    "CVE-2016-0938",
    "CVE-2016-0939",
    "CVE-2016-0940",
    "CVE-2016-0941",
    "CVE-2016-0942",
    "CVE-2016-0943",
    "CVE-2016-0944",
    "CVE-2016-0945",
    "CVE-2016-0946",
    "CVE-2016-0947",
    "CVE-2016-1111"
  );
  script_xref(name:"ZDI", value:"ZDI-16-273");

  script_name(english:"Adobe Acrobat < 11.0.14 / 15.006.30119 / 15.010.20056 Multiple Vulnerabilities (APSB16-02)");
  script_summary(english:"Checks the version of Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote Windows host is a
version prior to 11.0.14, 15.006.30119, or 15.010.20056. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple use-after-free errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-0932,
    CVE-2016-0934, CVE-2016-0937, CVE-2016-0940,
    CVE-2016-0941)

  - Multiple memory corruption issues exist that allow a
    remote attacker to execute arbitrary code.
    (CVE-2016-0931, CVE-2016-0933, CVE-2016-0936,
    CVE-2016-0938, CVE-2016-0939, CVE-2016-0942,
    CVE-2016-0944, CVE-2016-0945, CVE-2016-0946)

  - Multiple double-free errors exist that allow a remote
    attacker to execute arbitrary code. (CVE-2016-0935,
    CVE-2016-1111)

  - A flaw exists in the Global JavaScript API that allows
    a remote attacker to bypass restrictions and execute
    arbitrary code. (CVE-2016-0943)

  - A flaw exists in the download manager related to the
    directory search path used to find resources. A remote
    attacker can exploit this execute arbitrary code.
    (CVE-2016-0947)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/reader/apsb16-02.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 11.0.14 / 15.006.30119 / 15.010.20056 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Adobe Acrobat");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Adobe Acrobat";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];
verui   = install['display_version'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected is :
# 
# 11.x < 11.0.14
# DC Classic < 15.006.30119
# DC Continuous < 15.010.20056
if (
  (ver[0] == 11 && ver[1] == 0 && ver[2] <= 13) ||
  (ver[0] == 15 && ver[1] == 6 && ver[2] <= 30097) ||
  (ver[0] == 15 && ver[1] == 7 ) ||
  (ver[0] == 15 && ver[1] == 8 ) ||
  (ver[0] == 15 && ver[1] == 9 && ver[2] <= 20077)
)
{
  port = get_kb_item('SMB/transport');
  if(!port) port = 445;

  report = '\n  Path              : '+path+
           '\n  Installed version : '+verui+
           '\n  Fixed version     : 11.0.14 / 15.006.30119 / 15.010.20056' +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);
