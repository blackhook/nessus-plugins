#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88597);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2016-1723",
    "CVE-2016-1724",
    "CVE-2016-1725",
    "CVE-2016-1726",
    "CVE-2016-1727",
    "CVE-2016-1728"
  );
  script_bugtraq_id(81263);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-01-19-3");

  script_name(english:"Mac OS X : Apple Safari < 9.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote Mac OS X host is
prior to 9.0.3. It is, therefore, affected by the following
vulnerabilities :

  - Multiple memory corruption vulnerabilities exist in
    WebKit due to improper validation of user-supplied
    input. A remote attacker, via a specially crafted
    website, can exploit these issues to execute arbitrary
    code or cause a denial of service. (CVE-2016-1723,
    CVE-2016-1724, CVE-2016-1725, CVE-2016-1726,
    CVE-2016-1727)

  - A flaw exists in the Cascading Style Sheets (CSS)
    implementation in WebKit CSS when handling the
    'a:visited button' CSS selector while evaluating the
    height of the containing element. A remote attacker
    can exploit this, via a crafted website, to obtain
    sensitive browser history information. (CVE-2016-1728)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205730");
  # http://lists.apple.com/archives/security-announce/2016/Jan/msg00004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7e0375f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 9.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1727");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.(9|10|11)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9 / 10.10 / 10.11");

installed = get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path    = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "9.0.3";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
