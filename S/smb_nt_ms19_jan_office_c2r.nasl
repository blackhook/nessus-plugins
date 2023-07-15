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
  script_id(162100);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2019-0541",
    "CVE-2019-0559",
    "CVE-2019-0560",
    "CVE-2019-0561",
    "CVE-2019-0585"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft Office Products C2R (January 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists in the way
    that the MSHTML engine improperly validates input. An
    attacker could execute arbitrary code in the context of
    the current user. (CVE-2019-0541)

  - An information disclosure vulnerability exists when
    Microsoft Outlook improperly handles certain types of
    messages. An attacker who successfully exploited this
    vulnerability could gather information about the victim.
    An attacker could exploit this vulnerability by sending
    a specially crafted email to the victim. The update
    addresses the vulnerability by correcting the way
    Microsoft Outlook handles these types of messages.
    (CVE-2019-0559)

  - An information disclosure vulnerability exists when
    Microsoft Office improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data. (CVE-2019-0560)

  - An information disclosure vulnerability exists when
    Microsoft Office improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data. (CVE-2019-0560)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user. (CVE-2019-0585)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0585");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS19-01';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.8431.2366','channel': 'Deferred'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.9126.2351','channel': 'Deferred','channel_version': '1803'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.10730.20264','channel': 'Deferred','channel_version': '1808'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.10730.20264','channel': 'First Release for Deferred'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.11126.20192','channel': 'Current'},
    {'product':'Microsoft Office 2019','file':'mso.dll','fixed_version':'16.0.11126.20192','channel': '2019 Retail'},
    {'product':'Microsoft Office 2019','file':'mso.dll','fixed_version':'16.0.10340.20017','channel': '2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:"Office"
);