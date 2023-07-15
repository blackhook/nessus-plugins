#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140427);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-16875");
  script_xref(name:"MSKB", value:"4577352");
  script_xref(name:"MSFT", value:"MS20-4577352");
  script_xref(name:"IAVA", value:"2020-A-0413-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0118");

  script_name(english:"Security Updates for Exchange (September 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

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
    (CVE-2020-16875)");
  # https://support.microsoft.com/en-us/help/4577352/security-update-for-exchange-server-2019-and-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9455d8ba");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4577352 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16875");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange Server DlpUtils AddTenantDlpPolicy RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product': '2016',
    'unsupported_cu': 15,
    'cu' : 16,
    'min_version': '15.01.1979.0',
    'fixed_version': '15.01.1979.6',
    'kb': '4577352'
  },
  {
    'product' : '2016',
    'unsupported_cu' : 15,
    'cu' : 17,
    'min_version': '15.01.2044.0',
    'fixed_version': '15.01.2044.6',
    'kb': '4577352'
  },
 {
    'product' : '2019',
    'unsupported_cu' : 4,
    'cu' : 5,
    'min_version': '15.02.595.0',
    'fixed_version': '15.02.595.6',
    'kb': '4577352'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 4,
    'cu' : 6,
    'min_version': '15.02.659.0',
    'fixed_version': '15.02.659.6',
    'kb': '4577352'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS20-09',
  constraints:constraints,
  severity:SECURITY_WARNING
);