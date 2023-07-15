##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(162120);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2020-16933");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Security Updates for Microsoft Word Products C2R (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A security feature bypass vulnerability exists in
    Microsoft Word software when it fails to properly handle
    .LNK files. An attacker who successfully exploited the
    vulnerability could use a specially crafted file to
    perform actions in the security context of the current
    user. For example, the file could then take actions on
    behalf of the logged-on user with the same permissions
    as the current user.  (CVE-2020-16933)");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
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

var bulletin = 'MS20-10';

var constraints = [
    {'fixed_version':'16.0.12527.21236','channel': 'Microsoft 365 Apps on Windows 7'},
    {'fixed_version':'16.0.12527.21236','channel': 'Deferred','channel_version': '2002'},
    {'fixed_version':'16.0.11929.20966','channel': 'Deferred'},
    {'fixed_version':'16.0.13029.20708','channel': 'Enterprise Deferred'},
    {'fixed_version':'16.0.13127.20638','channel': 'Enterprise Deferred','channel_version': '2008'},
    {'fixed_version':'16.0.13127.20638','channel': 'First Release for Deferred'},
    {'fixed_version':'16.0.13231.20390','channel': '2016 Retail'},
    {'fixed_version':'16.0.13231.20390','channel': 'Current'},
    {'fixed_version':'16.0.13231.20390','channel': '2019 Retail'},
    {'fixed_version':'16.0.10367.20048','channel': '2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Word'
);
