#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(58319);
  script_version("1.17");
  script_cvs_date("Date: 2018/11/15 20:50:27");

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

  script_name(english:"Apple iTunes < 10.6 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a multimedia application that has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple iTunes installed on the remote Windows host is
older than 10.6.  Thus, it is reportedly affected by numerous memory
corruption vulnerabilities in its WebKit component."
  );
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/iTunes/Version");
fixed_version = "10.6.0.40";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/iTunes/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+fixed_version+'\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The iTunes "+version+" install in "+path+" is not affected.");
