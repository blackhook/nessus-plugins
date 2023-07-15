#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.


include("compat.inc");

if (description)
{
  script_id(162102);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2019-1264");

  script_name(english:"Security Updates for Microsoft Project C2R (September 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project installation on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - A security feature bypass vulnerability exists when
    Microsoft Office improperly handles input. An attacker
    who successfully exploited the vulnerability could
    execute arbitrary commands. In a file-sharing attack
    scenario, an attacker could provide a specially crafted
    document file designed to exploit the vulnerability, and
    then convince a user to open the document file and
    interact with the document by clicking a specific cell.
    The update addresses the vulnerability by correcting how
    Microsoft Office handles input. (CVE-2019-1264)");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1264");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS19-09';

var constraints = [
    {'fixed_version':'16.0.10730.20380','channel': 'Deferred'},
    {'fixed_version':'16.0.11328.20420','channel': 'Deferred','channel_version': '1902'},
    {'fixed_version':'16.0.11929.20300','channel': 'First Release for Deferred'},
    {'fixed_version':'16.0.11929.20300','channel': 'Current'},
    {'fixed_version':'16.0.11929.20300','channel': '2019 Retail'},
    {'fixed_version':'16.0.10350.20019','channel': '2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Project'
);