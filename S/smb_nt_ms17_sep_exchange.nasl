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
  script_id(103139);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2017-11761", "CVE-2017-8758");
  script_bugtraq_id(100723, 100731);
  script_xref(name:"MSFT", value:"MS17-4036108");

  script_name(english:"Security Updates for Exchange (September 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Microsoft Exchange Outlook Web Access (OWA) fails to
    properly handle web requests. An attacker who
    successfully exploited this vulnerability could perform
    script/content injection attacks and attempt to trick
    the user into disclosing sensitive information. To
    exploit the vulnerability, an attacker could send a
    specially crafted email message containing a malicious
    link to a user. Alternatively, an attacker could use a
    chat client to social engineer a user into clicking the
    malicious link. The security update addresses the
    vulnerability by correcting how Microsoft Exchange
    validates web requests. Note: In order to exploit this
    vulnerability, a user must click a maliciously crafted
    link from an attacker. (CVE-2017-8758)

  - An input sanitization issue exists with Microsoft
    Exchange that could potentially result in unintended
    Information Disclosure. An attacker who successfully
    exploited the vulnerability could identify the existence
    of RFC1918 addresses on the local network from a client
    on the Internet. An attacker could use this internal
    host information as part of a larger attack. To exploit
    the vulnerability, an attacker could include specially
    crafted tags in Calendar-related messages sent to an
    Exchange server. These specially-tagged messages could
    prompt the Exchange server to fetch information from
    internal servers. By observing telemetry from these
    requests, a client could discern properties of internal
    hosts intended to be hidden from the Internet. The
    update corrects the way that Exchange parses Calendar-
    related messages. (CVE-2017-11761)");
  # https://support.microsoft.com/en-us/help/4036108/description-of-the-security-update-for-microsoft-exchange-september-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?871d0058");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4036108");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11761");

   script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
   script_set_attribute(attribute:"exploit_available", value:"true");
   script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange ProxyShell RCE');
   script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

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
    'product': '2013',
    'cu': '17',
    'kb': '4036108',
    'min_version': '15.00.1320.0',
    'fixed_version': '15.00.1320.6'
  },
  {
    'product' : '2013',
    'cu': '16',
    'kb': '4036108',
    'min_version': '15.00.1293.0',
    'fixed_version': '15.00.1293.6'
  },
  {
    'product': '2013',
    'cu': '4',
    'kb': '4036108',
    'min_version': '15.00.847.0',
    'fixed_version': '15.00.847.57'
  },
  {
    'product' : '2016',
    'cu': '5',
    'kb': '4036108',
    'min_version': '15.01.845.0',
    'fixed_version': '15.01.845.39'
  },
  {
    'product': '2016',
    'cu': '6',
    'kb': '4036108',
    'min_version': '15.01.845.0',
    'fixed_version': '15.01.845.39'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS17-09',
  constraints:constraints,
  severity:SECURITY_WARNING
);