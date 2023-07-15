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
  script_id(162078);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2019-1084",
    "CVE-2019-1109",
    "CVE-2019-1111",
    "CVE-2019-1112"
  );
  script_bugtraq_id(
    108415,
    108965,
    108974,
    108975
  );

  script_name(english:"Security Updates for Microsoft Office Products C2R (July 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. They are, therefore, affected by multiple vulnerabilities:

  - An information disclosure vulnerability exists when Exchange allows creation of entities with Display Names having
    non-printable characters. An authenticated attacker could exploit this vulnerability by creating entities with
    invalid display names, which, when added to conversations, remain invisible. (CVE-2019-1084)

  - A spoofing vulnerability exists when Microsoft Office Javascript does not check the validity of the web page making
    a request to Office documents. An attacker who successfully exploited this vulnerability could read or write
    information in Office documents. (CVE-2019-1109)

  - A remote code execution vulnerability exists in Microsoft Excel software when the software fails to properly handle
    objects in memory. An attacker who successfully exploited the vulnerability could run arbitrary code in the context
    of the current user. If the current user is logged on with administrative user rights, an attacker could take
    control of the affected system. An attacker could then install programs; view, change, or delete data; or create
    new accounts with full user rights. Users whose accounts are configured to have fewer user rights on the system
    could be less impacted than users who operate with administrative user rights. Exploitation of the vulnerability
    requires that a user open a specially crafted file with an affected version of Microsoft Excel. In an email attack
    scenario, an attacker could exploit the vulnerability by sending the specially crafted file to the user and
    convincing the user to open the file. In a web-based attack scenario, an attacker could host a website (or leverage
    a compromised website that accepts or hosts user-provided content) containing a specially crafted file designed to
    exploit the vulnerability. An attacker would have no way to force users to visit the website. Instead, an attacker
    would have to convince users to click a link, typically by way of an enticement in an email or instant message, and
    then convince them to open the specially crafted file.(CVE-2019-1111)    

  - An information disclosure vulnerability exists when Microsoft Excel improperly discloses the contents of its memory.
    An attacker who exploited the vulnerability could use the information to compromise the user’s computer or data.
    To exploit the vulnerability, an attacker could craft a special document file and then convince the user to open it.
    An attacker must know the memory address location where the object was created. (CVE-2019-1112)
  
  The update addresses the vulnerability by changing the way certain Excel functions handle objects in memory.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1111");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1109");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
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

var bulletin = 'MS19-07';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.9126.2428','channel': 'Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.10730.20360','channel': 'Deferred','channel_version': '1808'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.11328.20368','channel': 'Deferred','channel_version': '1902'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.11328.20368','channel': 'First Release for Deferred'},
    {'product':'Microsoft Office 2016','file':'graph.exe','fixed_version':'16.0.11727.20244','channel': 'Current'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.11727.20244','channel': '2019 Retail'},
    {'product':'Microsoft Office 2019','file':'graph.exe','fixed_version':'16.0.10348.20020','channel': '2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:"Office"
);