#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101931);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/14  1:59:37");

  script_cve_id(
    "CVE-2017-7006",
    "CVE-2017-7011",
    "CVE-2017-7012",
    "CVE-2017-7018",
    "CVE-2017-7019",
    "CVE-2017-7020",
    "CVE-2017-7030",
    "CVE-2017-7034",
    "CVE-2017-7037",
    "CVE-2017-7038",
    "CVE-2017-7039",
    "CVE-2017-7040",
    "CVE-2017-7041",
    "CVE-2017-7042",
    "CVE-2017-7043",
    "CVE-2017-7046",
    "CVE-2017-7048",
    "CVE-2017-7049",
    "CVE-2017-7052",
    "CVE-2017-7055",
    "CVE-2017-7056",
    "CVE-2017-7059",
    "CVE-2017-7060",
    "CVE-2017-7061",
    "CVE-2017-7064"
  );
  script_bugtraq_id(
    99885,
    99886,
    99887,
    99888,
    99890
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-07-19-5");
  script_xref(name:"ZDI", value:"ZDI-17-489");

  script_name(english:"macOS : Apple Safari < 10.1.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the Safari version.");

  script_set_attribute(attribute:"synopsis", value:
"A web browser installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple Safari installed on the remote macOS or Mac OS X
host is prior to 10.1.2. It is, therefore, affected by multiple
vulnerabilities :

  - An information disclosure vulnerability exists in the
    WebKit component due to improper handling of SVG filters.
    An unauthenticated, remote attacker can exploit this,
    via a timing side-channel attack, to disclose sensitive
    cross-domain information. (CVE-2017-7006)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to spoof the address
    bar via a specially crafted website. (CVE-2017-7011)

  - Multiple memory corruption issues exists in the 'WebKit
    Web Inspector' component due to improper validation of
    input. An unauthenticated, remote attacker can exploit
    these issues, via a specially crafted web page, to
    execute arbitrary code. (CVE-2017-7012)

  - Multiple memory corruption issues exist in the WebKit
    component due to improper validation of input. An
    unauthenticated, remote attacker can exploit these
    issues, via a specially crafted web page, to execute
    arbitrary code. (CVE-2017-7018, CVE-2017-7020,
    CVE-2017-7030, CVE-2017-7034, CVE-2017-7037,
    CVE-2017-7039, CVE-2017-7040, CVE-2017-7041,
    CVE-2017-7042, CVE-2017-7043, CVE-2017-7046,
    CVE-2017-7048, CVE-2017-7049, CVE-2017-7052,
    CVE-2017-7055, CVE-2017-7056, CVE-2017-7061)

  - A memory corruption issue exists in the 'WebKit Page
    Loading' component due to improper validation of input.
    An unauthenticated, remote attacker can exploit this,
    via a specially crafted web page, to execute arbitrary
    code. (CVE-2017-7019)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in the WebKit component in the DOMParser due to
    improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote
    attacker can exploit these issue, via a specially
    crafted URL, to execute arbitrary script code in a
    user's browser session. (CVE-2017-7038, CVE-2017-7059)

  - A denial of service vulnerability exists in the Safari
    Printing component. An unauthenticated, remote attacker
    can exploit this, via a specially crafted web page, to
    create an infinite number of print dialogs.
    (CVE-2017-7060)

  - An unspecified memory initialization flaw exists in
    WebKit. A local attacker can exploit this, via a
    specially crafted application, to disclose restricted
    memory. (CVE-2017-7064)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207921");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2017/Jul/39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple Safari version 10.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X or macOS");

if (!preg(pattern:"Mac OS X 10\.(10|11|12)([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X Yosemite 10.10 / Mac OS X El Capitan 10.11 / macOS Sierra 10.12");

installed = get_kb_item_or_exit("MacOSX/Safari/Installed", exit_code:0);
path      = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version   = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "10.1.2";

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
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report, xss:true);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Safari", version, path);
