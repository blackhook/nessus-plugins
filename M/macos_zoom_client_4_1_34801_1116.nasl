#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(119241);
  script_version("1.4");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-15715");
  script_xref(name:"TRA", value:"TRA-2018-40");

  script_name(english:"Zoom Client for Meetings 4.x < 4.1.34801.1116 Message Spoofing Vulnerability (macOS)");
  script_summary(english:"Checks the Zoom Client for Meetings version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
message spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote macOS
or Mac OS X host is 4.x prior to 4.1.34801.1116. It is, therefore,
affected by a message spoofing vulnerability. An attacker could
leverage this vulnerability to perform restricted meeting operations.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2018-40");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 4.1.34801.1116 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zoom:zoom_client_for_meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_zoom_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "installed_sw/zoom");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

app_info = vcf::get_app_info(app:"zoom");

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "4", "fixed_version" : "4.1.34801.1116" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
