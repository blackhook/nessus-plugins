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
  script_id(146343);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2021-24085");
  script_xref(name:"MSKB", value:"4602269");
  script_xref(name:"MSFT", value:"MS21-4602269");
  script_xref(name:"IAVA", value:"2021-A-0069-S");

  script_name(english:"Security Updates for Microsoft Exchange Server (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by a spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
a spoofing vulnerability:

- A spoofing vulnerability exists. An attacker can
exploit this to perform actions with the privileges of
another user. (CVE-2021-24085)");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-and-2016-february-9-2021-kb4602269-2f3c3a74-094b-6669-2ea0-025101d11f1a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3d7c1580");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
 -KB4602269");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24085");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
    'product' : '2016',
    'unsupported_cu' : 17,
    'cu' : 18,
    'min_version': '15.01.2106.0',
    'fixed_version': '15.01.2106.8'
  },
  {
    'product': '2016',
    'unsupported_cu': 17,
    'cu' : 19,
    'min_version': '15.01.2176.0',
    'fixed_version': '15.01.2176.4'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 6,
    'cu' : 7,
    'min_version': '15.02.721.0',
    'fixed_version': '15.02.721.8'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 6,
    'cu' : 8,
    'min_version': '15.02.792.0',
    'fixed_version': '15.02.792.5'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS21-02',
  constraints:constraints,
  severity:SECURITY_WARNING
);