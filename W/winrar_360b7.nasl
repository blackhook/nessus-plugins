#
#  (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(22072);
  script_version("1.21");
 script_cvs_date("Date: 2019/08/28 10:08:38");

  script_cve_id("CVE-2006-3845");
  script_bugtraq_id(19043);

  script_name(english:"WinRAR LHA Filename Handling Buffer Overflows");
  script_summary(english:"Check the version of WinRAR");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is suffers from two
buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running WinRAR, an archive manager for Windows.

The version of WinRAR installed on the remote host is affected by two
stack-based buffer overflows when processing LHA files with specially-
crafted filenames. Successful exploitation of either issue enables an
attacker to execute arbitrary code subject to the privileges of the
current user.");
 script_set_attribute(attribute:"see_also", value:"http://www.hustlelabs.com/advisories/04072006_rarlabs.pdf");
 script_set_attribute(attribute:"see_also", value:"https://www.rarlab.com/rarnew.htm" );
 script_set_attribute(attribute:"solution", value:"Upgrade to WinRAR version 3.6.0 beta 7 (3.60.7.0) or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2006-3845");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/07/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/19");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winrar_win_installed.nbin");
  script_require_keys("installed_sw/RARLAB WinRAR", "SMB/Registry/Enumerated");
  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'RARLAB WinRAR', win_local:TRUE);

constraints = [
  { 'fixed_version' : '3.60.beta7', fixed_display: '3.60 Beta 7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
