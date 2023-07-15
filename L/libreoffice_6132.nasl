#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121544);
  script_version("1.7");
  script_cvs_date("Date: 2019/10/31 15:18:52");

  script_cve_id("CVE-2018-16858");

  script_name(english:"LibreOffice 6.1.x < 6.1.3.2 Arbitrary Code Execution");
  script_summary(english:"Checks the version of LibreOffice.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by an 
an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of LibreOffice installed on the remote Windows host is
6.1.x prior to 6.1.3.2. It is, therefore, affected by an an arbitrary
code execution vulnerability as a result of a path traversal
vulnerability allowing the ability to run any local python script,
in addition to being able to pass user defined parameters to default 
python modules and functions included with libreoffice.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://insert-script.blogspot.com/2019/02/libreoffice-cve-2018-16858-remote-code.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b37c8646");
  script_set_attribute(attribute:"solution", value:
"Upgrade to LibreOffice version 6.1.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16858");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'LibreOffice Macro Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:libreoffice:libreoffice");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("libreoffice_installed.nasl");
  script_require_keys("installed_sw/LibreOffice", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
app_info = vcf::get_app_info(app:"LibreOffice");

constraints = [{"min_version":"6.1","fixed_version":"6.1.3.2"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
