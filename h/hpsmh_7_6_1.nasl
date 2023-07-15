#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103530);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-8743",
    "CVE-2017-12544",
    "CVE-2017-12545",
    "CVE-2017-12546",
    "CVE-2017-12547",
    "CVE-2017-12548",
    "CVE-2017-12549",
    "CVE-2017-12550",
    "CVE-2017-12551",
    "CVE-2017-12552",
    "CVE-2017-12553"
  );
  script_xref(name:"HP", value:"HPSBMU03753");
  script_xref(name:"IAVB", value:"2017-B-0132");

  script_name(english:"HP System Management Homepage < 7.6.1 Multiple Vulnerabilities (HPSBMU03753)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of HP System Management Homepage
(SMH) hosted on the remote web server is prior to 7.6.1. It is,
therefore, affected by multiple vulnerabilities including
multiple local and remote code execution vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.hpe.com/hpsc/doc/public/display?docId=hpesbmu03753en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05d894b4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP System Management Homepage (SMH) version 7.6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12553");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("compaq_wbem_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

# Only Linux and Windows are affected
os = get_kb_item_or_exit("Host/OS");
if ("Windows" >!< os && "Linux" >!< os) audit(AUDIT_OS_NOT, "Windows or Linux", os);

port = get_http_port(default:2381, embedded:TRUE);
app = "hp_smh";
get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['dir'];
version = install['version'];
prod = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");
source_line = get_kb_item("www/"+port+"/hp_smh/source");

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, prod, build_url(port:port, qs:dir+"/") );

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  audit(AUDIT_VER_FORMAT, version);

if (ver_compare(ver:version_alt, fix:"7.6.1", strict:FALSE) == -1)
{
  report = '\n  Product           : ' + prod;
  if (!isnull(source_line))
    report += '\n  Version source    : ' + source_line;
  report +=
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 7.6.1' +
    '\n';

  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report, xss:TRUE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, prod, port, version);
