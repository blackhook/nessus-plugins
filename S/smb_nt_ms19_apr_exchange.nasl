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
  script_id(123975);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/20");

  script_cve_id("CVE-2019-0817", "CVE-2019-0858");
  script_xref(name:"MSKB", value:"4491413");
  script_xref(name:"MSKB", value:"4487563");
  script_xref(name:"MSFT", value:"MS19-4491413");
  script_xref(name:"MSFT", value:"MS19-4487563");

  script_name(english:"Security Updates for Exchange (April 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A spoofing vulnerability exists in Microsoft Exchange
    Server when Outlook Web Access (OWA) fails to properly
    handle web requests. An attacker who successfully
    exploited the vulnerability could perform script or
    content injection attacks, and attempt to trick the user
    into disclosing sensitive information. An attacker could
    also redirect the user to a malicious website that could
    spoof content or the vulnerability could be used as a
    pivot to chain an attack with other vulnerabilities in
    web services.  (CVE-2019-0817, CVE-2019-0858)");
  # https://support.microsoft.com/en-us/help/4491413/update-rollup-27-for-exchange-server-2010-service-pack-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91648e9b");
  # https://support.microsoft.com/en-us/help/4487563/description-of-the-security-update-for-microsoft-exchange-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?582a33f9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4491413
  -KB4487563");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0817");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-0858");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/10");

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
    'fixed_version': '14.03.452.0',
    'kb': '4491413'
  },
   {
    'product' : '2013',
    'min_version': '15.00.1473.0',
    'fixed_version': '15.00.1473.3',
    'cu' : 22,
    'kb': '4487563'
  },
  {
    'product' : '2016',
    'cu' : 12,
    'min_version': '15.01.1713.0',
    'fixed_version': '15.01.1713.6',
    'kb': '4487563'
  },
  {
    'product': '2016',
    'cu' : 11,
    'min_version': '15.01.1591.0',
    'fixed_version': '15.01.1591.16',
    'kb': '4487563'
  },
  {
    'product' : '2019',
    'cu' : 1,
    'min_version': '15.02.330.0',
    'fixed_version': '15.02.330.7',
    'kb': '4487563'
  },
  {
    'product' : '2019',
    'min_version': '15.02.221.0',
    'fixed_version': '15.02.221.16',
    'kb': '4487563'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS19-04',
  constraints:constraints,
  severity:SECURITY_WARNING
);
