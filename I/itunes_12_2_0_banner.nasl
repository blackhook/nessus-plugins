#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86600);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id(
    "CVE-2014-3192",
    "CVE-2014-4452",
    "CVE-2014-4459",
    "CVE-2014-4466",
    "CVE-2014-4468",
    "CVE-2014-4469",
    "CVE-2014-4470",
    "CVE-2014-4471",
    "CVE-2014-4472",
    "CVE-2014-4473",
    "CVE-2014-4474",
    "CVE-2014-4475",
    "CVE-2014-4476",
    "CVE-2014-4477",
    "CVE-2014-4479",
    "CVE-2015-1068",
    "CVE-2015-1069",
    "CVE-2015-1070",
    "CVE-2015-1071",
    "CVE-2015-1072",
    "CVE-2015-1073",
    "CVE-2015-1074",
    "CVE-2015-1075",
    "CVE-2015-1076",
    "CVE-2015-1077",
    "CVE-2015-1078",
    "CVE-2015-1079",
    "CVE-2015-1080",
    "CVE-2015-1081",
    "CVE-2015-1082",
    "CVE-2015-1083",
    "CVE-2015-1119",
    "CVE-2015-1120",
    "CVE-2015-1121",
    "CVE-2015-1122",
    "CVE-2015-1124",
    "CVE-2015-1152",
    "CVE-2015-1153",
    "CVE-2015-1154"
  );
  script_bugtraq_id(
    70273,
    71137,
    71144,
    71438,
    71442,
    71444,
    71445,
    71449,
    71451,
    71459,
    71461,
    71462,
    72329,
    72330,
    72331,
    73972,
    74523,
    74525,
    74526
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-06-30-6");

  script_name(english:"Apple iTunes < 12.2 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes running on the remote host is prior to
12.2. It is, therefore, affected by multiple vulnerabilities due to
memory corruption issues in the WebKit component. An attacker can
exploit these to cause a denial of service or execute arbitrary code.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT204949");
  # https://lists.apple.com/archives/security-announce/2015/Jun/msg00006.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?103c0dda");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple version iTunes 12.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-4466");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixed_version = "12.2.0.145";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + source +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : ' + fixed_version + 
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
