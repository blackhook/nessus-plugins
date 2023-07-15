#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104360);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-13783",
    "CVE-2017-13784",
    "CVE-2017-13785",
    "CVE-2017-13788",
    "CVE-2017-13791",
    "CVE-2017-13792",
    "CVE-2017-13793",
    "CVE-2017-13794",
    "CVE-2017-13795",
    "CVE-2017-13796",
    "CVE-2017-13797",
    "CVE-2017-13798",
    "CVE-2017-13802",
    "CVE-2017-13803"
  );

  script_name(english:"Apple iTunes < 12.7.1 WebKit Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.7.1. It is, therefore, affected by multiple vulnerabilities
in webkit as referenced in the HT208224 advisory.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208224");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13803");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixed_version = "12.7.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  report = '\n  Version source    : ' + source +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fixed_version +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
