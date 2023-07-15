#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(162039);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2020-1229");
  script_xref(name:"IAVA", value:"2020-A-0255-S");

  script_name(english:"Security Updates for Microsoft Office Products C2R (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A security feature bypass vulnerability exists in
    Microsoft Outlook when Office fails to enforce security
    settings configured on a system. An attacker who
    successfully exploited this vulnerability could cause a
    system to load remote images. These images could
    disclose the IP address of the targeted system to the
    attacker. Exploitation of the vulnerability requires
    that a user open a specially crafted image with an
    affected version of Microsoft Office software.
    (CVE-2020-1229)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1229");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS20-06';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.11328.20602','channel': 'Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.11929.20838','channel': 'Deferred','channel_version': '1908'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.12527.20720','channel': 'Microsoft 365 Apps on Windows 7'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.12527.20720','channel': 'First Release for Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.12827.20336','channel': 'Current'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.12827.20336','channel': '2019 Retail'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.10361.20002','channel': '2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Office'
);