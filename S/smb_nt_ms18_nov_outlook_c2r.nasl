##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##
include("compat.inc");

if (description)
{
  script_id(162091);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2018-8522",
    "CVE-2018-8524",
    "CVE-2018-8558",
    "CVE-2018-8576",
    "CVE-2018-8579",
    "CVE-2018-8582"
  );

  script_name(english:"Security Updates for Outlook C2R (November 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that Microsoft Outlook parses specially modified rule
    export files. An attacker who successfully exploited
    this vulnerability could take control of an affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8582)

  - A remote code execution vulnerability exists in
    Microsoft Outlook software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2018-8522,
    CVE-2018-8524, CVE-2018-8576)");
  # https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?941265c6");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
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

var bulletin = 'MS18-11';

var constraints = [
  { 'channel':'Deferred', 'channel_version':'1803',  'fixed_version': '16.0.9126.2315'},
  { 'channel':'Deferred', 'fixed_version': '16.0.8431.2329'},
  { 'channel':'First Release for Deferred',  'fixed_version': '16.0.10730.20205'},
  { 'channel':'Current',  'fixed_version': '16.0.11001.20108'},
  { 'channel':'2019 Volume',  'fixed_version': '16.0.10338.20019'},
  { 'channel':'2019 Retail',  'fixed_version': '16.0.11001.20108'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Outlook'
);

