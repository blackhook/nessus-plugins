#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc. 
##

#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159707);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/23");

  script_cve_id("CVE-2022-24473", "CVE-2022-26901");
  script_xref(name:"IAVA", value:"2022-A-0140-S");
  script_xref(name:"IAVA", value:"2022-A-0144-S");

  script_name(english:"Security Updates for Microsoft Office Products (April 2022) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office product installed on the remote host is missing security updates. It is, therefore, affected by
two remote code execution vulnerabilities in Excel.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ed1b90");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#april-12-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e636435");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-26901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "installed_sw/Microsoft Excel");

  exit(0);
}

include('vcf_extras_office.inc');

var apps = make_list('Microsoft Excel');
var app_info = vcf::microsoft::office_for_mac::get_app_info(apps:apps);

var constraints = [
  {'min_version':'16.17.0', 'fixed_version':'16.60', 'fixed_display':'16.60 (22041000)'}
];

vcf::microsoft::office_for_mac::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  os_min_lvl:'10.15.0'
);

