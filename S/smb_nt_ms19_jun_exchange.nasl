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
  script_id(125881);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_xref(name:"MSKB", value:"4503027");
  script_xref(name:"MSKB", value:"4503028");
  script_xref(name:"MSFT", value:"MS19-4503027");
  script_xref(name:"MSFT", value:"MS19-4503028");

  script_name(english:"Security Updates for Exchange (June 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing security updates. It is, therefore, affected by
a spoofing vulnerability when Outlook Web Access fails to property handle web requests.

An unauthenticated, remote attacker can exploit this by sending in a specially crafted link to a tricked user who 
clicks on the malicious link & activates the exploit.");
  # https://support.microsoft.com/en-us/help/4503027/security-update-for-microsoft-exchange-server-2019-june-11-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62ce3d54");
  # https://support.microsoft.com/en-us/help/4503028/security-update-for-microsoft-exchange-server-2013-and-2010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57677259");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4503027
  -KB4503028");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

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
    'min_version': '14.03.461.0',
    'fixed_version': '14.03.461.1',
    'kb': '4503028'
  },
   {
    'product' : '2013',
    'cu' : 22,
    'min_version': '15.00.1473.0',
    'fixed_version': '15.00.1473.5'
  },
  {
    'product' : '2016',
    'cu' : 11,
    'min_version': '15.01.1591.0',
    'fixed_version': '15.01.1591.17',
    'kb': '4503028'
  },
   {
    'product' : '2016',
    'cu' : 12,
    'min_version': '15.01.1713.0',
    'fixed_version': '15.01.1713.7',
    'kb': '4503028'
  },
  {
    'product' : '2019',
    'cu' : 1,
    'min_version': '15.02.330.0',
    'fixed_version': '15.02.330.8',
    'kb': '4503027'
  },
  {
    'product' : '2019',
    'min_version': '15.02.221.0',
    'fixed_version': '15.02.221.17',
    'kb': '4503027'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS19-06',
  constraints:constraints,
  severity:SECURITY_WARNING
);