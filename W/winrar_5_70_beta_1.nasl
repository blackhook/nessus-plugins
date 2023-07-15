#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122448);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-20250",
    "CVE-2018-20251",
    "CVE-2018-20252",
    "CVE-2018-20253"
  );
  script_bugtraq_id(106948);
  script_xref(name:"IAVA", value:"2020-A-0007");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/08/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0078");

  script_name(english:"RARLAB WinRAR < 5.70 Beta 1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of RARLAB WinRAR installed on the remote Windows host is
prior to 5.70 Beta 1. It is, therefore, affected by the following
vulnerabilities :

  - An error exists in the file 'unacev2.dll' related to
    the 'filename' field, that allows a specially crafted
    ACE archive to overwrite files outside the destination
    folder. Such files could be in the system startup
    locations, and thus, lead to arbitrary code execution on
    next boot. (CVE-2018-20250)

  - An input-validation error exists in the file
    'unacev2.dll' related to handling ACE archives and
    filenames that allows path traversal pattern checking
    to be bypassed. (CVE-2018-20251)

  - An out-of-bounds write error exists related to handling
    ACE and RAR file parsing that allows arbitrary code
    execution. (CVE-2018-20252)

  - An out-of-bounds write error exists related to handling
    LHA and LZH file parsing that allows arbitrary code
    execution. (CVE-2018-20253)");
  script_set_attribute(attribute:"see_also", value:"https://research.checkpoint.com/extracting-code-execution-from-winrar/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/Ridter/acefile");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WinRAR version 5.70 Beta 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20253");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'RARLAB WinRAR ACE Format Input Validation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rarlab:winrar");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winrar_win_installed.nbin");
  script_require_keys("installed_sw/RARLAB WinRAR", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"RARLAB WinRAR", win_local:TRUE);

constraints = [
  { "fixed_version" : "5.70.beta1", fixed_display: "5.70 Beta 1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
