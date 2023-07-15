#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117878);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id(
    "CVE-2018-4261",
    "CVE-2018-4262",
    "CVE-2018-4263",
    "CVE-2018-4264",
    "CVE-2018-4265",
    "CVE-2018-4266",
    "CVE-2018-4267",
    "CVE-2018-4270",
    "CVE-2018-4271",
    "CVE-2018-4272",
    "CVE-2018-4273",
    "CVE-2018-4278",
    "CVE-2018-4284",
    "CVE-2018-4293"
  );
  script_bugtraq_id(
    104844,
    542127,
    542130,
    542207
  );

  script_name(english:"Apple iTunes < 12.8 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.8. It is, therefore, affected by multiple vulnerabilities
in WebKit as referenced in the HT208933 advisory.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-ie/HT208933");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes version 12.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4284");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixed_version = "12.8";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  report = '\n  Version source    : ' + source +
           '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fixed_version +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
