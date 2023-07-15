#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105689);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753");
  script_bugtraq_id(102371, 102376);
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"macOS : Apple Safari <= 11.0.2 (11604.4.7.1.6 / 12604.4.7.1.6 / 13604.4.7.10.6) Information Disclosure (Spectre)");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote macOS or Mac OS X
host is prior to 11.0.2, or is 11.0.2 and missing the January 8th patch.
It is, therefore, affected by a vulnerability that exists within
microprocessors utilizing speculative execution and indirect branch
prediction, which may allow an attacker with local user access to
disclose information via a side-channel analysis.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208397");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208403");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 11.0.2 and apply the vendor
patch.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5753");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed", "MacOSX/Safari/Detailed_Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X or macOS");

if (!preg(pattern:"Mac OS X 10\.(11|12|13)([^0-9]|$)", string:os))
{
  audit(AUDIT_OS_NOT, "Mac OS X El Capitan 10.11 / macOS Sierra 10.12 / macOS High Sierra 10.13");
} 

installed = get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path      = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version   = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);
detailed_version   = get_kb_item_or_exit("MacOSX/Safari/Detailed_Version", exit_code:1);

fixed_version = "11.0.2";

if (preg(pattern:"Mac OS X 10\.13\.2($|[^0-9])", string:os))
  detailed_fixed_version = "13604.4.7.1.6";
else if (preg(pattern:"Mac OS X 10\.12\.6($|[^0-9])", string:os))
  detailed_fixed_version = "12604.4.7.1.6";
else if (preg(pattern:"Mac OS X 10\.11\.6($|[^0-9])", string:os))
  detailed_fixed_version = "11604.4.7.1.6";
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version + " (" + detailed_version + ")", path);

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fixed_version
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version")
  );
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else if (
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == 0 &&
  ver_compare(ver:detailed_version, fix:detailed_fixed_version, strict:FALSE) == -1
)
{
  report = report_items_str(
    report_items:make_array(
      "Path", path,
      "Installed version", version,
      "Fixed version", fixed_version,
      "Installed detailed version", detailed_version,
      "Fixed detailed version", detailed_fixed_version
    ),
    ordered_fields:make_list("Path", "Installed version", "Fixed version", "Installed detailed version", "Fixed detailed version")
  );
  security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version + " (" + detailed_version + ")", path);
