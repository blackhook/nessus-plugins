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
  script_id(162067);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2020-0850", "CVE-2020-0892");

  script_name(english:"Security Updates for Microsoft Word Products C2R (March 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by a Remote Code Execution Vulnerability. (CVE-2020-0850, CVE-2020-0892)");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates.
It is, therefore, affected by affected by the following vulnerability:

  - A remote code execution vulnerability exists in Microsoft Word software when it fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability could use a specially crafted file to perform 
    actions in the security context of the current user. For example, the file could then take actions on behalf 
    of the logged-on user with the same permissions as the current user.

    To exploit the vulnerability, a user must open a specially crafted file with an affected version of Microsoft Word 
    software. In an email attack scenario, an attacker could exploit the vulnerability by sending the specially crafted
    file to the user and convincing the user to open the file. In a web-based attack scenario, an attacker could host a
    website (or leverage a compromised website that accepts or hosts user-provided content) that contains a specially 
    crafted file that is designed to exploit the vulnerability. However, an attacker would have no way to force the 
    user to visit the website. Instead, an attacker would have to convince the user to click a link, typically by way 
    of an enticement in an email or Instant Messenger message, and then convince the user to open the specially 
    crafted file. (CVE-2020-0850, CVE-2020-0892)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0892");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-0850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
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

var bulletin = 'MS20-03';

var constraints = [
    {'fixed_version':'16.0.11328.20554','channel': 'Deferred'},
    {'fixed_version':'16.0.11929.20648','channel': 'Deferred','channel_version': '1908'},
    {'fixed_version':'16.0.12527.20278','channel': 'Microsoft 365 Apps on Windows 7'},
    {'fixed_version':'16.0.12527.20278','channel': 'First Release for Deferred'},
    {'fixed_version':'16.0.12527.20278','channel': 'Current'},
    {'fixed_version':'16.0.12527.20278','channel': '2019 Retail'},
    {'fixed_version':'16.0.10357.20081','channel': '2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Word'
);