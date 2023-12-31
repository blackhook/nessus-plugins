#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55639);
  script_version("1.47");
  script_cvs_date("Date: 2018/07/27 18:38:15");

  script_cve_id(
    "CVE-2010-1383",
    "CVE-2010-1420",
    "CVE-2010-1823",
    "CVE-2010-3829",
    "CVE-2011-0164",
    "CVE-2011-0195",
    "CVE-2011-0200",
    "CVE-2011-0201",
    "CVE-2011-0202",
    "CVE-2011-0204",
    "CVE-2011-0206",
    "CVE-2011-0214",
    "CVE-2011-0215",
    "CVE-2011-0216",
    "CVE-2011-0217",
    "CVE-2011-0218",
    "CVE-2011-0219",
    "CVE-2011-0221",
    "CVE-2011-0222",
    "CVE-2011-0223",
    "CVE-2011-0225",
    "CVE-2011-0232",
    "CVE-2011-0233",
    "CVE-2011-0234",
    "CVE-2011-0235",
    "CVE-2011-0237",
    "CVE-2011-0238",
    "CVE-2011-0240",
    "CVE-2011-0241",
    "CVE-2011-0242",
    "CVE-2011-0244",
    "CVE-2011-0253",
    "CVE-2011-0254",
    "CVE-2011-0255",
    "CVE-2011-0981",
    "CVE-2011-0983",
    "CVE-2011-1107",
    "CVE-2011-1109",
    "CVE-2011-1114",
    "CVE-2011-1115",
    "CVE-2011-1117",
    "CVE-2011-1121",
    "CVE-2011-1188",
    "CVE-2011-1190",
    "CVE-2011-1203",
    "CVE-2011-1204",
    "CVE-2011-1288",
    "CVE-2011-1293",
    "CVE-2011-1295",
    "CVE-2011-1296",
    "CVE-2011-1449",
    "CVE-2011-1451",
    "CVE-2011-1453",
    "CVE-2011-1457",
    "CVE-2011-1462",
    "CVE-2011-1774",
    "CVE-2011-1797",
    "CVE-2011-3443"
  );
  script_bugtraq_id(
    43228,
    46262,
    46614,
    46703,
    46785,
    47029,
    47604,
    47668,
    48416,
    48426,
    48427,
    48429,
    48437,
    48820,
    48823,
    48824,
    48825,
    48827,
    48828,
    48831,
    48832,
    48833,
    48837,
    48839,
    48840,
    48841,
    48842,
    48843,
    48844,
    48845,
    48846,
    48847,
    48848,
    48849,
    48850,
    48851,
    48852,
    48853,
    48854,
    48855,
    48856,
    48857,
    48858,
    48859,
    48860
  );
  script_xref(name:"EDB-ID", value:"17575");
  script_xref(name:"EDB-ID", value:"17993");
  script_xref(name:"MSVR", value:"MSVR11-009");

  script_name(english:"Safari < 5.1 Multiple Vulnerabilities");
  script_summary(english:"Checks Safari's version number");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Safari installed on the remote Windows host is earlier
than 5.1.  As such, it is potentially affected by numerous issues in
the following components :

  - CFNetwork
  - ColorSync
  - CoreFoundation
  - CoreGraphics
  - International Components for Unicode
  - ImageIO
  - libxslt
  - libxml
  - Safari
  - WebKit"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4808");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Jul/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Safari 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-678");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple Safari Webkit libxslt Arbitrary File Creation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2018 Tenable Network Security, Inc.");

  script_dependencies("safari_installed.nasl");
  script_require_keys("SMB/Safari/FileVersion");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/Safari/FileVersion");

version_ui = get_kb_item("SMB/Safari/ProductVersion");
if (isnull(version_ui)) version_ui = version;

if (ver_compare(ver:version, fix:"5.34.50.0") == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/Safari/Path");
    if (isnull(path)) path = "n/a";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_ui +
      '\n  Fixed version     : 5.1 (7534.50)\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The remote host is not affected since Safari " + version_ui + " is installed.");
