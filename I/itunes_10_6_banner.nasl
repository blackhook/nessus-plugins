#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58320);
  script_version("1.20");
  script_cvs_date("Date: 2018/11/15 20:50:24");

  script_cve_id(
    "CVE-2011-2825",
    "CVE-2011-2833",
    "CVE-2011-2846",
    "CVE-2011-2847",
    "CVE-2011-2854",
    "CVE-2011-2855",
    "CVE-2011-2857",
    "CVE-2011-2860",
    "CVE-2011-2866",
    "CVE-2011-2867",
    "CVE-2011-2868",
    "CVE-2011-2869",
    "CVE-2011-2870",
    "CVE-2011-2871",
    "CVE-2011-2872",
    "CVE-2011-2873",
    "CVE-2011-2877",
    "CVE-2011-3885",
    "CVE-2011-3888",
    "CVE-2011-3897",
    "CVE-2011-3908",
    "CVE-2011-3909",
    "CVE-2012-0591",
    "CVE-2012-0592",
    "CVE-2012-0593",
    "CVE-2012-0594",
    "CVE-2012-0595",
    "CVE-2012-0596",
    "CVE-2012-0597",
    "CVE-2012-0598",
    "CVE-2012-0599",
    "CVE-2012-0600",
    "CVE-2012-0601",
    "CVE-2012-0602",
    "CVE-2012-0603",
    "CVE-2012-0604",
    "CVE-2012-0605",
    "CVE-2012-0606",
    "CVE-2012-0607",
    "CVE-2012-0608",
    "CVE-2012-0609",
    "CVE-2012-0610",
    "CVE-2012-0611",
    "CVE-2012-0612",
    "CVE-2012-0613",
    "CVE-2012-0614",
    "CVE-2012-0615",
    "CVE-2012-0616",
    "CVE-2012-0617",
    "CVE-2012-0618",
    "CVE-2012-0619",
    "CVE-2012-0620",
    "CVE-2012-0621",
    "CVE-2012-0622",
    "CVE-2012-0623",
    "CVE-2012-0624",
    "CVE-2012-0625",
    "CVE-2012-0626",
    "CVE-2012-0627",
    "CVE-2012-0628",
    "CVE-2012-0629",
    "CVE-2012-0630",
    "CVE-2012-0631",
    "CVE-2012-0632",
    "CVE-2012-0633",
    "CVE-2012-0634",
    "CVE-2012-0635",
    "CVE-2012-0636",
    "CVE-2012-0637",
    "CVE-2012-0638",
    "CVE-2012-0639",
    "CVE-2012-0648"
  );
  script_bugtraq_id(
    49279,
    49658,
    49938,
    50360,
    50642,
    51041,
    52363,
    52365,
    53148
  );

  script_name(english:"Apple iTunes < 10.6 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
10.6. It is, therefore, affected by multiple memory corruption
vulnerabilities in the WebKit component. Note that these only affect
iTunes for Windows.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-147/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/267");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT202433");
  script_set_attribute(attribute:"see_also", value:"https://lists.apple.com/archives/security-announce/2012/Mar/msg00000.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 10.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("iTunes/sharing");
  script_require_ports("Services/www", 3689);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

get_kb_item_or_exit("iTunes/" + port + "/enabled");

type = get_kb_item_or_exit("iTunes/" + port + "/type");
source = get_kb_item_or_exit("iTunes/" + port + "/source");
version = get_kb_item_or_exit("iTunes/" + port + "/version");

if (type != 'Windows') audit(AUDIT_OS_NOT, "Windows");

fixed_version = "10.6";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
