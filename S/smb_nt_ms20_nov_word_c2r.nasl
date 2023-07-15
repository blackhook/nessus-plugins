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
  script_id(162058);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2020-17020");
  script_xref(name:"IAVA", value:"2020-A-0563-S");

  script_name(english:"Security Updates for Microsoft Word Products C2R (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Word installation on the remote host is missing a security update. It is, therefore, affected by 
an unspecified remote code execution vulnerability. An attacker can exploit this vulnerability by tricking a user into
opening a specially crafted Office file.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17020");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

var bulletin = 'MS20-11';

var constraints = [
    {'fixed_version':'16.0.12527.21330','channel': 'Microsoft 365 Apps on Windows 7'},
    {'fixed_version':'16.0.12527.21330','channel': 'Deferred','channel_version': '2002'},
    {'fixed_version':'16.0.11929.20974','channel': 'Deferred'},
    {'fixed_version':'16.0.13127.20760','channel': 'Enterprise Deferred'},
    {'fixed_version':'16.0.13231.20514','channel': 'Enterprise Deferred','channel_version': '2009'},
    {'fixed_version':'16.0.13127.20760','channel': 'First Release for Deferred'},
    {'fixed_version':'16.0.13328.20356','channel': '2016 Retail'},
    {'fixed_version':'16.0.13328.20356','channel': 'Current'},
    {'fixed_version':'16.0.13328.20356','channel': '2019 Retail','channel_version': '2010'},
    {'fixed_version':'16.0.13328.20356','channel': '2019 Retail','channel_version': '2004'},
    {'fixed_version':'16.0.13231.20514','channel': '2019 Retail','channel_version': '2009'},
    {'fixed_version':'16.0.13127.20760','channel': '2019 Retail','channel_version': '2008'},
    {'fixed_version':'16.0.12527.21330','channel': '2019 Retail','channel_version': '2002'},
    {'fixed_version':'16.0.11929.20974','channel': '2019 Retail','channel_version': '1908'},
    {'fixed_version':'16.0.10368.20035','channel': '2019 Volume'},
    {'fixed_version':'16.0.11929.20974','channel': '2019 Retail'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_NOTE,
  bulletin:bulletin,
  subproduct:'Word'
);
