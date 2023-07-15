#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('compat.inc');

if (description)
{
  script_id(174167);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/20");

  script_cve_id("CVE-2023-28285", "CVE-2023-28311");

  script_name(english:"Security Updates for Microsoft Office Products (Apr 2023) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office product installed on the remote host is missing security updates. It is, therefore, 
affected by multiple vulnerabilities:

  - Microsoft Office Remote Code Execution Vulnerability. (CVE-2023-28285)

  - Microsoft Word Remote Code Execution Vulnerability. (CVE-2023-28311)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-for-mac
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43ed1b90");
  # https://learn.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac#april-11-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0471d2fc");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28311");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");

  exit(0);
}

include('vcf_extras_office.inc');

var apps = make_list('Microsoft Outlook', 'Microsoft Excel', 'Microsoft Word',
                     'Microsoft PowerPoint','Microsoft OneNote');

var app_info = vcf::microsoft::office_for_mac::get_app_info(apps:apps);

var constraints = [
  {'min_version':'16.17.0', 'fixed_version':'16.72', 'fixed_display':'16.72 (23040900)'}
];

vcf::microsoft::office_for_mac::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  os_min_lvl:'11.0'
);
