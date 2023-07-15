#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(121022);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2019-0586", "CVE-2019-0588");
  script_xref(name:"MSKB", value:"4468742");
  script_xref(name:"MSKB", value:"4471389");
  script_xref(name:"MSFT", value:"MS19-4468742");
  script_xref(name:"MSFT", value:"MS19-4471389");

  script_name(english:"Security Updates for Exchange (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An information disclosure vulnerability exists when the
    Microsoft Exchange PowerShell API grants calendar
    contributors more view permissions than intended.
    (CVE-2019-0588)

  - A remote code execution vulnerability exists in
    Microsoft Exchange software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the System user. An
    attacker could then install programs; view, change, or
    delete data; or create new accounts. Exploitation of the
    vulnerability requires that a specially crafted email be
    sent to a vulnerable Exchange server. The security
    update addresses the vulnerability by correcting how
    Microsoft Exchange handles objects in memory.
    (CVE-2019-0586)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4468742");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4471389");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4468742
  -KB4471389");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0586");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::exchange::get_app_info();

var constraints =
[
  {
    'product' : '2010',
    'min_version': '14.3.0.0',
    'fixed_version': '14.03.435.0',
    'kb':'4468742'
  },
   {
    'product' : '2013',
    'cu' : 21,
    'min_version': '15.00.1395.0',
    'fixed_version': '15.00.1395.10',
    'kb':'4471389'
  },
  {
    'product' : '2016',
    'cu' : 10,
    'min_version': '15.01.1531.0',
    'fixed_version': '15.01.1531.10',
    'kb':'4471389'
  },
   {
    'product' : '2016',
    'cu' : 11,
    'min_version': '15.01.1591.0',
    'fixed_version': '15.01.1591.13',
    'kb':'4471389'
  },
  {
    'product' : '2019',
    'cu' : 0,
    'min_version': '15.02.221.0',
    'fixed_version': '15.02.221.14',
    'kb':'4471389'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS19-01',
  constraints:constraints,
  severity:SECURITY_WARNING
);