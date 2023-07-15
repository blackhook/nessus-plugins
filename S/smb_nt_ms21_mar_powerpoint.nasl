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
  script_id(147216);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/01");

  script_cve_id("CVE-2021-27056");
  script_xref(name:"MSKB", value:"4493227");
  script_xref(name:"MSKB", value:"4504702");
  script_xref(name:"MSKB", value:"4493224");
  script_xref(name:"MSFT", value:"MS21-4493227");
  script_xref(name:"MSFT", value:"MS21-4504702");
  script_xref(name:"MSFT", value:"MS21-4493224");
  script_xref(name:"IAVA", value:"2021-A-0128");

  script_name(english:"Security Updates for Microsoft PowerPoint Products (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft PowerPoint Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft PowerPoint Products are missing a security
update. It is, therefore, affected by the following
vulnerability:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-27056)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493227");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4504702");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4493224");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4493227
  -KB4504702
  -KB4493224
");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-27056");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS21-03';
var kbs = make_list(
  '4493224',
  '4504702',
  '4493227'
);
var severity = SECURITY_WARNING;

var constraints = [
  { 'kb':'4504702',  'fixed_version': '14.0.7266.5000', 'sp' : 2},
  { 'kb':'4493227',  'fixed_version': '15.0.5325.1000', 'sp' : 1},
  { 'kb':'4493224', 'channel':'MSI', 'fixed_version': '16.0.5131.1000', 'sp' : 0}
];

vcf::microsoft::office_product::check_version_and_report(
  kbs:kbs,
  constraints:constraints,
  severity:severity,
  bulletin:bulletin,
  subproduct:'PowerPoint'
);

