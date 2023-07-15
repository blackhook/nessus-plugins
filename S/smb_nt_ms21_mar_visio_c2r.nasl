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
  script_id(161756);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/14");

  script_cve_id("CVE-2021-27055");

  script_name(english:"Security Updates for Microsoft Visio Products C2R (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visio Products are missing a security update.
It is, therefore, affected by the following vulnerability:

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2021-27055)");
  # https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#march-09-2021
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b73190a");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27055");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_visio_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS21-03';

var constraints = [
  { 'channel':'Deferred', 'channel_version':'2008',  'fixed_version': '16.0.13127.21348'},
  { 'channel':'Microsoft 365 Apps on Windows 7',  'fixed_version': '16.0.12527.21686'},
  { 'channel':'Deferred',  'fixed_version': '16.0.12527.21686'},
  { 'channel':'Enterprise Deferred', 'channel_version':'2101',  'fixed_version': '16.0.13628.20528'},
  { 'channel':'Enterprise Deferred',  'fixed_version': '16.0.13530.20628'},
  { 'channel':'First Release for Deferred',  'fixed_version': '16.0.13801.20294'},
  { 'channel':'2016 Retail',  'fixed_version': '16.0.13801.20294'},
  { 'channel':'Current',  'fixed_version': '16.0.13801.20294'},
  { 'channel':'2019 Volume',  'fixed_version': '16.0.10372.20060'},
  { 'channel':'2019 Retail',  'fixed_version': '16.0.13801.20294'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_WARNING,
  bulletin:bulletin,
  subproduct:'Visio'
);

