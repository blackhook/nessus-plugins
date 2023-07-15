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
  script_id(133617);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/19");

  script_cve_id("CVE-2020-0688", "CVE-2020-0692");
  script_xref(name:"MSKB", value:"4536987");
  script_xref(name:"MSKB", value:"4536988");
  script_xref(name:"MSKB", value:"4536989");
  script_xref(name:"MSFT", value:"MS20-4536987");
  script_xref(name:"MSFT", value:"MS20-4536988");
  script_xref(name:"MSFT", value:"MS20-4536989");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2020-0122");
  script_xref(name:"CEA-ID", value:"CEA-2020-0017");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");
  script_xref(name:"CEA-ID", value:"CEA-2020-0019");

  script_name(english:"Security Updates for Exchange (February 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in
    Microsoft Exchange Server. An attacker who successfully
    exploited this vulnerability could gain the same rights
    as any other user of the Exchange server. This could
    allow the attacker to perform activities such as
    accessing the mailboxes of other users. Exploitation of
    this vulnerability requires Exchange Web Services (EWS)
    to be enabled and in use in an affected environment.
    (CVE-2020-0692)

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
    (CVE-2020-0688)");
  # https://support.microsoft.com/en-us/help/4536987/security-update-for-exchange-server-2019-and-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cac6add1");
  # https://support.microsoft.com/en-us/help/4536988/description-of-the-security-update-for-microsoft-exchange-server-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dce9375f");
  # https://support.microsoft.com/en-us/help/4536989/security-update-for-exchange-server-2010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b23bced2");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4536987
  -KB4536988
  -KB4536989");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0688");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exchange Control Panel ViewState Deserialization');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'fixed_version': '14.03.496.0',
    'kb': '4536989'
  },
  {
    'product' : '2013',
    'unsupported_cu' : 21,
    'cu' : 23,
    'min_version': '15.00.1497.0',
    'fixed_version': '15.00.1497.6',
    'kb': '4536988'
  },
  {
    'product' : '2013',
    'unsupported_cu' : 21,
    'cu' : 22,
    'min_version': '15.00.1497.0',
    'fixed_version': '15.00.1497.6',
    'kb': '4536988'
  },
  {
    'product' : '2016',
    'unsupported_cu' : 13,
    'cu' : 15,
    'min_version': '15.01.1913.0',
    'fixed_version': '15.01.1913.7',
    'kb': '4536987'
  },
  {
    'product': '2016',
    'unsupported_cu': 13,
    'cu' : 14,
    'min_version': '15.01.1847.0',
    'fixed_version': '15.01.1847.7',
    'kb': '4536987'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 2,
    'cu' : 3,
    'min_version': '15.02.464.0',
    'fixed_version': '15.02.464.11',
    'kb': '4536987'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 2,
    'cu' : 4,
    'min_version': '15.02.529.0',
    'fixed_version': '15.02.529.8',
    'kb': '4536987'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS20-02',
  constraints:constraints,
  severity:SECURITY_WARNING
);