#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('compat.inc');

if (description)
{
  script_id(162093);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2020-1229");
  script_xref(name:"IAVA", value:"2020-A-0255-S");

  script_name(english:"Security Feature Bypass Vulnerability for Word C2R (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products is missing a security update, and Therefore is affected by 
a security feature bypass vulnerability. An attacker who exploited this vulnerability 
could cause a system to load remote images which could disclose the IP address of the 
targeted system to the attacker.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
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

var constraints = [
    {'fixed_version':'16.0.11328.20602','channel': 'Deferred'},
    {'fixed_version':'16.0.11929.20838','channel': 'Deferred','channel_version': '1908'},
    {'fixed_version':'16.0.12527.20720','channel': 'Microsoft 365 Apps on Windows 7'},
    {'fixed_version':'16.0.12527.20720','channel': 'First Release for Deferred'},
    {'fixed_version':'16.0.12827.20336','channel': 'Current'},
    {'fixed_version':'16.0.12827.20336','channel': '2019 Retail'},
    {'fixed_version':'16.0.10361.20002','channel': '2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Word'
);