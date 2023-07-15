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
  script_id(141491);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-16969");
  script_xref(name:"MSKB", value:"4581424");
  script_xref(name:"MSFT", value:"MS20-4581424");
  script_xref(name:"IAVA", value:"2020-A-0461-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Security Updates for Exchange (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - An information disclosure vulnerability exists in how
    Microsoft Exchange validates tokens when handling
    certain messages. An attacker who successfully exploited
    the vulnerability could use this to gain further
    information from a user.  (CVE-2020-16969)");
  # https://support.microsoft.com/en-us/help/4581424/description-of-the-security-update-for-exchange-server-october-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?039d66e9");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4581424 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16969");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/16");

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
    'product' : '2013',
    'unsupported_cu' : 22,
    'cu' : 23,
    'min_version': '15.00.1497.0',
    'fixed_version': '15.00.1497.7',
    'kb': '4581424'
  },
  {
    'product' : '2016',
    'unsupported_cu' : 16,
    'cu' : 18,
    'min_version': '15.01.2106.0',
    'fixed_version': '15.01.2106.3',
    'kb': '4581424'
  },
  {
    'product': '2016',
    'unsupported_cu': 16,
    'cu' : 17,
    'min_version': '15.01.2044.0',
    'fixed_version': '15.01.2044.7',
    'kb': '4581424'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 5,
    'cu' : 7,
    'min_version': '15.02.721.0',
    'fixed_version': '15.02.721.3',
    'kb': '4581424'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 5,
    'cu' : 6,
    'min_version': '15.02.659.0',
    'fixed_version': '15.02.659.7',
    'kb': '4581424'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS20-10',
  constraints:constraints,
  severity:SECURITY_WARNING
);