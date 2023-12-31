#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78597);
  script_version("1.6");
  script_cvs_date("Date: 2018/11/15 20:50:27");

  script_cve_id(
    "CVE-2013-2871",
    "CVE-2013-2875",
    "CVE-2013-2909",
    "CVE-2013-2926",
    "CVE-2013-2927",
    "CVE-2013-2928",
    "CVE-2013-5195",
    "CVE-2013-5196",
    "CVE-2013-5197",
    "CVE-2013-5198",
    "CVE-2013-5199",
    "CVE-2013-5225",
    "CVE-2013-5228",
    "CVE-2013-6625",
    "CVE-2013-6635",
    "CVE-2013-6663",
    "CVE-2014-1268",
    "CVE-2014-1269",
    "CVE-2014-1270",
    "CVE-2014-1289",
    "CVE-2014-1290",
    "CVE-2014-1291",
    "CVE-2014-1292",
    "CVE-2014-1293",
    "CVE-2014-1294",
    "CVE-2014-1298",
    "CVE-2014-1299",
    "CVE-2014-1300",
    "CVE-2014-1301",
    "CVE-2014-1302",
    "CVE-2014-1303",
    "CVE-2014-1304",
    "CVE-2014-1305",
    "CVE-2014-1307",
    "CVE-2014-1308",
    "CVE-2014-1309",
    "CVE-2014-1310",
    "CVE-2014-1311",
    "CVE-2014-1312",
    "CVE-2014-1313",
    "CVE-2014-1323",
    "CVE-2014-1324",
    "CVE-2014-1325",
    "CVE-2014-1326",
    "CVE-2014-1327",
    "CVE-2014-1329",
    "CVE-2014-1330",
    "CVE-2014-1331",
    "CVE-2014-1333",
    "CVE-2014-1334",
    "CVE-2014-1335",
    "CVE-2014-1336",
    "CVE-2014-1337",
    "CVE-2014-1338",
    "CVE-2014-1339",
    "CVE-2014-1340",
    "CVE-2014-1341",
    "CVE-2014-1342",
    "CVE-2014-1343",
    "CVE-2014-1344",
    "CVE-2014-1362",
    "CVE-2014-1363",
    "CVE-2014-1364",
    "CVE-2014-1365",
    "CVE-2014-1366",
    "CVE-2014-1367",
    "CVE-2014-1368",
    "CVE-2014-1382",
    "CVE-2014-1384",
    "CVE-2014-1385",
    "CVE-2014-1386",
    "CVE-2014-1387",
    "CVE-2014-1388",
    "CVE-2014-1389",
    "CVE-2014-1390",
    "CVE-2014-1713",
    "CVE-2014-1731",
    "CVE-2014-4410",
    "CVE-2014-4411",
    "CVE-2014-4412",
    "CVE-2014-4413",
    "CVE-2014-4414",
    "CVE-2014-4415"
  );
  script_bugtraq_id(
    64361,
    67553,
    67572
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-10-16-6");

  script_name(english:"Apple iTunes < 12.0.1 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
prior to 12.0.1. It is, therefore, affected by multiple
vulnerabilities due to the included version of WebKit. The errors
could lead to application crashes or arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT203115");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/533723/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 12.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("installed_sw/iTunes Version", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Ensure this is Windows
get_kb_item_or_exit("SMB/Registry/Enumerated");

app_id = 'iTunes Version';
install = get_single_install(app_name:app_id, exit_if_unknown_ver:TRUE);

version = install["version"];
path = install["path"];

fixed_version = "12.0.1.26";
if (ver_compare(ver:version, fix:fixed_version) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);
