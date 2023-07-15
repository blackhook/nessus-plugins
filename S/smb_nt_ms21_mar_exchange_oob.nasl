#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147003);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/31");

  script_cve_id(
    "CVE-2021-26412",
    "CVE-2021-26854",
    "CVE-2021-26855",
    "CVE-2021-26857",
    "CVE-2021-26858",
    "CVE-2021-27065",
    "CVE-2021-27078"
  );
  script_xref(name:"MSKB", value:"5000871");
  script_xref(name:"MSFT", value:"MS21-5000871");
  script_xref(name:"IAVA", value:"2021-A-0111-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/04/16");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2021-0014");
  script_xref(name:"CEA-ID", value:"CEA-2021-0018");
  script_xref(name:"CEA-ID", value:"CEA-2021-0013");

  script_name(english:"Security Updates for Microsoft Exchange Server (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker could exploit this to
  execute unauthorized arbitrary code. (CVE-2021-26412, CVE-2021-26854,
  CVE-2021-26855, CVE-2021-26857, CVE-2021-26858, CVE-2021-27065,
  CVE-2021-27078)");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-march-2-2021-kb5000871-9800a6bb-0a21-4ee7-b9da-fa85b3e1d23b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14b26c05");
  # https://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fedb98e4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB5000871");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26855");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Exchange ProxyLogon RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product' : '2013',
    'unsupported_cu' : 22,
    'cu' : 23,
    'min_version': '15.00.1497.0',
    'fixed_version': '15.00.1497.12',
    'kb': '5000871'
  },
  {
     'product' : '2016',
     'unsupported_cu' : 13,
     'cu' : 14,
     'min_version': '15.01.1847.0',
     'fixed_version': '15.01.1847.12',
     'kb': '5000871'
  },
  {
     'product': '2016',
     'unsupported_cu': 13,
     'cu' : 15,
     'min_version': '15.01.1913.0',
     'fixed_version': '15.01.1913.12',
     'kb': '5000871'
  },
  {
     'product' : '2016',
     'unsupported_cu' : 13,
     'cu' : 16,
     'min_version': '15.01.1979.0',
     'fixed_version': '15.01.1979.8',
     'kb': '5000871'
  },
  {
      'product': '2016',
      'unsupported_cu': 13,
      'cu' : 18,
      'min_version': '15.01.2106.0',
      'fixed_version': '15.01.2106.13',
      'kb': '5000871'
  },
  {
    'product' : '2016',
    'unsupported_cu' : 13,
    'cu' : 19,
    'min_version': '15.01.2176.0',
    'fixed_version': '15.01.2176.9',
    'kb': '5000871'
  },
  {
      'product' : '2019',
      'unsupported_cu' : 3,
      'cu' : 4,
      'min_version': '15.02.529.0',
      'fixed_version': '15.02.529.13',
      'kb': '5000871'
   },
  {
      'product' : '2019',
      'unsupported_cu' : 3,
      'cu' : 5,
      'min_version': '15.02.595.0',
      'fixed_version': '15.02.595.8',
      'kb': '5000871'
    },
  {
     'product' : '2019',
     'unsupported_cu' : 3,
     'cu' : 6,
     'min_version': '15.02.659.0',
     'fixed_version': '15.02.659.12',
     'kb': '5000871'
   },
  {
    'product' : '2019',
    'unsupported_cu' : 3,
    'cu' : 7,
    'min_version': '15.02.721.0',
    'fixed_version': '15.02.721.13',
    'kb': '5000871'
   },
  {
    'product' : '2019',
    'unsupported_cu' : 3,
    'cu' : 8,
    'min_version': '15.02.792.0',
    'fixed_version': '15.02.792.10',
    'kb': '5000871'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS20-12',
  constraints:constraints,
  severity:SECURITY_WARNING
);