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
  script_id(162029);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");
  script_cve_id(
    "CVE-2019-0538",
    "CVE-2019-0540",
    "CVE-2019-0582",
    "CVE-2019-0669",
    "CVE-2019-0671",
    "CVE-2019-0672",
    "CVE-2019-0673",
    "CVE-2019-0674",
    "CVE-2019-0675"
  );
  script_bugtraq_id(106419, 106433);

  script_name(english:"Security Updates for Microsoft Office Products C2R (February 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. They
are, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists when the Windows Jet
    Database Engine improperly handles objects in memory. An attacker
    who successfully exploited this vulnerability could execute
    arbitrary code on a victim system. An attacker could exploit this
    vulnerability by enticing a victim to open a specially crafted
    file. (CVE-2019-0538, CVE-2019-0582)

  - A security feature bypass vulnerability exists when Microsoft
    Office does not validate URLs. An attacker could send a victim a
    specially crafted file, which could trick the victim into
    entering credentials. An attacker who successfully exploited this
    vulnerability could perform a phishing attack. (CVE-2019-0540)

  - An information disclosure vulnerability exists when Microsoft
    Excel improperly discloses the contents of its memory. An
    attacker who exploited the vulnerability could use the
    information to compromise the user's computer or data. To exploit
    the vulnerability, an attacker could craft a special document
    file and then convince the user to open it. An attacker must know
    the memory address location where the object was created.
    (CVE-2019-0669)

  - A remote code execution vulnerability exists when the Microsoft
    Office Access Connectivity Engine improperly handles objects in
    memory. An attacker who successfully exploited this vulnerability
    could execute arbitrary code on a victim system. An attacker
    could exploit this vulnerability by enticing a victim to open a
    specially crafted file. (CVE-2019-0671,  CVE-2019-0672, 
    CVE-2019-0673,  CVE-2019-0674, CVE-2019-0675)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0675");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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

var bulletin = 'MS19-02';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.8431.2372','channel': 'Deferred'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.9126.2356','channel': 'Deferred','channel_version': '1803'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.10730.20280','channel': 'Deferred','channel_version': '1808'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.10730.20280','channel': 'First Release for Deferred'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.11231.20164','channel': 'Current'},
    {'product':'Microsoft Office 2019','file':'mso.dll','fixed_version':'16.0.11231.20164','channel': '2019 Retail'},
    {'product':'Microsoft Office 2019','file':'mso.dll','fixed_version':'16.0.10341.20010','channel': '2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:"Office"
);