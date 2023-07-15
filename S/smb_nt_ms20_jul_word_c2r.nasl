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
  script_id(162050);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id(
    "CVE-2020-1342",
    "CVE-2020-1445",
    "CVE-2020-1446",
    "CVE-2020-1447",
    "CVE-2020-1448"
  );
  script_xref(name:"IAVA", value:"2020-A-0312-S");

  script_name(english:"Security Updates for Microsoft Word Products C2R (July 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates. It
is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Office improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2020-1445)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-1446,
    CVE-2020-1447, CVE-2020-1448)

  - An information disclosure vulnerability exists when
    Microsoft Office software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Office software. The security
    update addresses the vulnerability by properly
    initializing the affected variable. (CVE-2020-1342)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1447");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
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

var bulletin = 'MS20-07';

var constraints = [
    {'fixed_version':'16.0.11328.20624','channel': 'Deferred'},
    {'fixed_version':'16.0.11929.20904','channel': 'Deferred','channel_version': '1908'},
    {'fixed_version':'16.0.12730.20602','channel': 'Enterprise Deferred'},
    {'fixed_version':'16.0.12827.20538','channel': 'Enterprise Deferred','channel_version': '2005'},
    {'fixed_version':'16.0.12527.20880','channel': 'Microsoft 365 Apps on Windows 7'},
    {'fixed_version':'16.0.12527.20880','channel': 'First Release for Deferred'},
    {'fixed_version':'16.0.13001.20384','channel': 'Current'},
    {'fixed_version':'16.0.13001.20384','channel': '2019 Retail'},
    {'fixed_version':'16.0.10363.20015','channel': '2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Word'
);