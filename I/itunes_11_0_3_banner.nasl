#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66499);
  script_version("1.16");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id(
    "CVE-2012-2824",
    "CVE-2012-2857",
    "CVE-2012-3748",
    "CVE-2012-5112",
    "CVE-2013-0879",
    "CVE-2013-0912",
    "CVE-2013-0948",
    "CVE-2013-0949",
    "CVE-2013-0950",
    "CVE-2013-0951",
    "CVE-2013-0952",
    "CVE-2013-0953",
    "CVE-2013-0954",
    "CVE-2013-0955",
    "CVE-2013-0956",
    "CVE-2013-0958",
    "CVE-2013-0959",
    "CVE-2013-0960",
    "CVE-2013-0961",
    "CVE-2013-0991",
    "CVE-2013-0992",
    "CVE-2013-0993",
    "CVE-2013-0994",
    "CVE-2013-0995",
    "CVE-2013-0996",
    "CVE-2013-0997",
    "CVE-2013-0998",
    "CVE-2013-0999",
    "CVE-2013-1000",
    "CVE-2013-1001",
    "CVE-2013-1002",
    "CVE-2013-1003",
    "CVE-2013-1004",
    "CVE-2013-1005",
    "CVE-2013-1006",
    "CVE-2013-1007",
    "CVE-2013-1008",
    "CVE-2013-1010",
    "CVE-2013-1011",
    "CVE-2013-1014"
  );
  script_bugtraq_id(
    54203,
    54749,
    55867,
    56362,
    57576,
    57580,
    57581,
    57582,
    57584,
    57585,
    57586,
    57587,
    57588,
    57589,
    57590,
    58388,
    58495,
    58496,
    59941,
    59944,
    59953,
    59954,
    59955,
    59956,
    59957,
    59958,
    59959,
    59960,
    59963,
    59964,
    59965,
    59967,
    59970,
    59971,
    59972,
    59973,
    59974,
    59976,
    59977
  );
  script_xref(name:"EDB-ID", value:"28081");

  script_name(english:"Apple iTunes < 11.0.3 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
11.0.3. It is, therefore, affected by multiple vulnerabilities :

  - An error exists related to certificate validation. A
    man-in-the-middle attacker can exploit this to spoof
    HTTPS servers, which allows the disclosure of sensitive
    information or the application to trust data from
    untrusted sources. Note that this issue affects the
    application regardless of the operating system.
    (CVE-2013-1014)

  - The version of WebKit included in iTunes contains
    several errors that can lead to memory corruption and
    arbitrary code execution. The vendor states that one
    possible vector is a man-in-the-middle attack while the
    application browses the 'iTunes Store'. Please note that
    these vulnerabilities only affect the application when
    it is running on a Windows host.
    (CVE-2012-2824, CVE-2012-2857, CVE-2012-3748,
    CVE-2012-5112, CVE-2013-0879, CVE-2013-0912,
    CVE-2013-0948, CVE-2013-0949, CVE-2013-0950,
    CVE-2013-0951, CVE-2013-0952, CVE-2013-0953,
    CVE-2013-0954, CVE-2013-0955, CVE-2013-0956,
    CVE-2013-0958, CVE-2013-0959, CVE-2013-0960,
    CVE-2013-0961, CVE-2013-0991, CVE-2013-0992,
    CVE-2013-0993, CVE-2013-0994, CVE-2013-0995,
    CVE-2013-0996, CVE-2013-0997, CVE-2013-0998,
    CVE-2013-0999, CVE-2013-1000, CVE-2013-1001,
    CVE-2013-1002, CVE-2013-1003, CVE-2013-1004,
    CVE-2013-1005, CVE-2013-1006, CVE-2013-1007,
    CVE-2013-1008, CVE-2013-1010, CVE-2013-1011)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-107/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-108/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-109/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5766");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/May/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526623/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes 11.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5112");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (type == 'AppleTV') audit(AUDIT_LISTEN_NOT_VULN, "iTunes on AppleTV", port, version);

fixed_version = "11.0.3";

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
