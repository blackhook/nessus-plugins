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
  script_id(105187);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2017-11932");
  script_bugtraq_id(102060);
  script_xref(name:"MSKB", value:"4045655");
  script_xref(name:"MSFT", value:"MS17-4045655");

  script_name(english:"Security Updates for Exchange (December 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is missing
a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host is missing
a security update. It is, therefore, affected by the following
vulnerability :

  - A spoofing vulnerability exists in Microsoft Exchange
    Server when Outlook Web Access (OWA) fails to properly
    handle web requests. An attacker who successfully
    exploited the vulnerability could perform script or
    content injection attacks, and attempt to trick the user
    into disclosing sensitive information. An attacker could
    also redirect the user to a malicious website that could
    spoof content or be used as a pivot to chain an attack
    with other vulnerabilities in web services.
    (CVE-2017-11932)");
  # https://support.microsoft.com/en-us/help/4045655/description-of-the-security-update-for-microsoft-exchange-december-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac5daff4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4045655 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11932");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'cu': '18',
    'kb': '4045655',
    'min_version': '15.00.1347.0',
    'fixed_version': '15.00.1347.3'
  },
  {
    'product': '2013',
    'cu': '17',
    'kb': '4045655',
    'min_version': '15.00.1320.0',
    'fixed_version': '15.00.1320.7'
  },
  {
    'product' : '2016',
    'cu': '7',
    'kb': '4045655',
    'min_version': '15.01.1261.0',
    'fixed_version': '15.01.1261.37'
  },
  {
    'product': '2016',
    'cu': '6',
    'kb': '4045655',
    'min_version': '15.01.1034.0',
    'fixed_version': '15.01.1034.33'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS17-12',
  constraints:constraints,
  severity:SECURITY_WARNING
);