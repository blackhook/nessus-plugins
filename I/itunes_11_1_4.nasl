#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72104);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/26");

  script_cve_id(
    "CVE-2011-3102",
    "CVE-2012-0841",
    "CVE-2012-2807",
    "CVE-2012-2825",
    "CVE-2012-2870",
    "CVE-2012-2871",
    "CVE-2012-5134",
    "CVE-2013-1024",
    "CVE-2013-1037",
    "CVE-2013-1038",
    "CVE-2013-1039",
    "CVE-2013-1040",
    "CVE-2013-1041",
    "CVE-2013-1042",
    "CVE-2013-1043",
    "CVE-2013-1044",
    "CVE-2013-1045",
    "CVE-2013-1046",
    "CVE-2013-1047",
    "CVE-2013-2842",
    "CVE-2013-5125",
    "CVE-2013-5126",
    "CVE-2013-5127",
    "CVE-2013-5128",
    "CVE-2014-1242"
  );
  script_bugtraq_id(
    52107,
    53540,
    54203,
    54718,
    55331,
    56684,
    60067,
    60368,
    62551,
    62553,
    62554,
    62556,
    62557,
    62558,
    62559,
    62560,
    62563,
    62565,
    62567,
    62568,
    62569,
    62570,
    62571,
    65088
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-01-22-1");

  script_name(english:"Apple iTunes < 11.1.4 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes installed on the remote Windows host is
older than 11.1.4. It is, therefore, potentially affected by several
issues :

  - The included versions of WebKit, libxml, and libxslt
    contain several errors that could lead to memory
    corruption and possibly arbitrary code execution. The
    vendor notes that one possible attack vector is a
    man-in-the-middle attack while the application browses
    the 'iTunes Store'. (CVE-2011-3102, CVE-2012-0841,
    CVE-2012-2807, CVE-2012-2825, CVE-2012-2870,
    CVE-2012-2871, CVE-2012-5134, CVE-2013-1037,
    CVE-2013-1038, CVE-2013-1039, CVE-2013-1040,
    CVE-2013-1041, CVE-2013-1042, CVE-2013-1043,
    CVE-2013-1044, CVE-2013-1045, CVE-2013-1046,
    CVE-2013-1047, CVE-2013-2842, CVE-2013-5125,
    CVE-2013-5126, CVE-2013-5127, CVE-2013-5128)

  - An error exists related to text tracks in movie files
    that could allow denial of service or arbitrary code
    execution. (CVE-2013-1024)

  - An error exists related to the iTunes Tutorials window
    that could allow an attacker in a privileged network
    location to inject content. (CVE-2014-1242)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6001");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/530870/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apple iTunes 11.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2842");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/iTunes/Version");
path = get_kb_item_or_exit("SMB/iTunes/Path");

fixed_version = "11.1.4.62";
if (ver_compare(ver:version, fix:fixed_version) < 0)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+fixed_version+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);
