#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83473);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id(
    "CVE-2014-8452",
    "CVE-2014-9160",
    "CVE-2014-9161",
    "CVE-2015-3046",
    "CVE-2015-3047",
    "CVE-2015-3048",
    "CVE-2015-3049",
    "CVE-2015-3050",
    "CVE-2015-3051",
    "CVE-2015-3052",
    "CVE-2015-3053",
    "CVE-2015-3054",
    "CVE-2015-3055",
    "CVE-2015-3056",
    "CVE-2015-3057",
    "CVE-2015-3058",
    "CVE-2015-3059",
    "CVE-2015-3060",
    "CVE-2015-3061",
    "CVE-2015-3062",
    "CVE-2015-3063",
    "CVE-2015-3064",
    "CVE-2015-3065",
    "CVE-2015-3066",
    "CVE-2015-3067",
    "CVE-2015-3068",
    "CVE-2015-3069",
    "CVE-2015-3070",
    "CVE-2015-3071",
    "CVE-2015-3072",
    "CVE-2015-3073",
    "CVE-2015-3074",
    "CVE-2015-3075",
    "CVE-2015-3076"
  );
  script_bugtraq_id(
    71567,
    74599,
    74600,
    74601,
    74602,
    74603,
    74604,
    74618
  );

  script_name(english:"Adobe Reader < 10.1.14 / 11.0.11 Multiple Vulnerabilities (APSB15-10)");
  script_summary(english:"Checks the version of Adobe Reader.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Reader on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Reader installed on the remote host is a version
prior to 10.1.14 / 11.0.11. It is, therefore, affected by the
following vulnerabilities :

  - A buffer overflow condition exists in CoolType.dll due
    to improper validation of user-supplied input. A remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2014-9160)

  - An out-of-bounds read flaw exists in CoolType.dll due
    to improper validation of user-supplied input. A remote
    attacker, via a specially crafted PDF file, can cause
    the application to crash and disclose memory contents.
    (CVE-2014-9161).

  - Multiple input validation, NULL pointer dereference, and
    use-after-free flaws exist that allow memory corruption,
    arbitrary code execution, and buffer overflow attacks.
    (CVE-2015-3047,CVE-2015-3048, CVE-2015-3049,
    CVE-2015-3050, CVE-2015-3051, CVE-2015-3052,
    CVE-2015-3053, CVE-2015-3054, CVE-2015-3055,
    CVE-2015-3056, CVE-2015-3057, CVE-2015-3058,
    CVE-2015-3059, CVE-2015-3070, CVE-2015-3075,
    CVE-2015-3076)

  - Multiple unspecified flaws in the JavaScript API allow
    an attacker to bypass JavaScript API restrictions.
    (CVE-2015-3060, CVE-2015-3061, CVE-2015-3062,
    CVE-2015-3063, CVE-2015-3064, CVE-2015-3065,
    CVE-2015-3066, CVE-2015-3067, CVE-2015-3068,
    CVE-2015-3069, CVE-2015-3071, CVE-2015-3072,
    CVE-2015-3073, CVE-2015-3074) 

  - An XML external entity injection flaw exists that allows
    information disclosure. (CVE-2014-8452)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/reader/apsb15-10.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 10.1.14 / 11.0.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3076");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_reader_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Reader");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item("Host/MacOSX/Version");
if (empty_or_null(os)) audit(AUDIT_OS_NOT, "Mac OS X");

app_name = "Adobe Reader";
install = get_single_install(app_name:app_name);

version = install['version'];
path    = install['path'];

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Affected for Mac is :
# 10.x < 10.1.14
# 11.x < 11.0.11
if (
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 14) ||
  (ver[0] == 11 && ver[1] == 0 && ver[2] < 11)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Path              : '+path+
             '\n  Installed version : '+version+
             '\n  Fixed version     : 10.1.11 / 11.0.11' +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
