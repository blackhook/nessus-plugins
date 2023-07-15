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
  script_id(126581);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2019-1084", "CVE-2019-1136", "CVE-2019-1137");
  script_xref(name:"MSKB", value:"4509410");
  script_xref(name:"MSKB", value:"4509409");
  script_xref(name:"MSKB", value:"4509408");
  script_xref(name:"MSFT", value:"MS19-4509410");
  script_xref(name:"MSFT", value:"MS19-4509409");
  script_xref(name:"MSFT", value:"MS19-4509408");
  script_xref(name:"IAVA", value:"2019-A-0229-S");

  script_name(english:"Security Updates for Exchange (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A cross-site-scripting (XSS) vulnerability exists when
    Microsoft Exchange Server does not properly sanitize a
    specially crafted web request to an affected Exchange
    server. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected server. The attacker who successfully
    exploited the vulnerability could then perform cross-
    site scripting attacks on affected systems and run
    script in the security context of the current user. The
    attacks could allow the attacker to read content that
    the attacker is not authorized to read, use the victim's
    identity to take actions on the Exchange server on
    behalf of the user, such as change permissions and
    delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that Exchange Server
    properly sanitizes web requests. (CVE-2019-1137)

  - An information disclosure vulnerability exists when
    Exchange allows creation of entities with Display Names
    having non-printable characters. An authenticated
    attacker could exploit this vulnerability by creating
    entities with invalid display names, which, when added
    to conversations, remain invisible. This security update
    addresses the issue by validating display names upon
    creation in Microsoft Exchange, and by rendering invalid
    display names correctly in Microsoft Outlook clients.
    (CVE-2019-1084)

  - An elevation of privilege vulnerability exists in
    Microsoft Exchange Server. An attacker who successfully
    exploited this vulnerability could gain the same rights
    as any other user of the Exchange server. This could
    allow the attacker to perform activities such as
    accessing the mailboxes of other users. Exploitation of
    this vulnerability requires Exchange Web Services (EWS)
    to be enabled and in use in an affected environment.
    (CVE-2019-1136)");
  # https://support.microsoft.com/en-us/help/4509410/description-of-the-security-update-for-microsoft-exchange-server-2010
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?252d2640");
  # https://support.microsoft.com/en-us/help/4509409/description-of-the-security-update-for-microsoft-exchange-server-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a7f2f98");
  # https://support.microsoft.com/en-us/help/4509408/description-of-the-security-update-for-microsoft-exchange-server-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b960286e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4509410
  -KB4509409
  -KB4509408");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1136");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'min_version': '14.03.468.0',
    'fixed_version': '14.03.468.1',
    'kb': '4509410'
  },
   {
    'product' : '2013',
    'cu' : 22,
    'min_version': '15.00.1497.0',
    'fixed_version': '15.00.1497.3',
    'kb': '4509409'
  },
  {
    'product' : '2016',
    'cu' : 12,
    'min_version': '15.01.1713.0',
    'fixed_version': '15.01.1713.8',
    'kb': '4509409'
  },
  {
     'product' : '2016',
     'cu' : 13,
     'min_version': '15.01.1779.0',
     'fixed_version': '15.01.1779.4',
     'kb': '4509409'
  },
  {
      'product' : '2019',
      'cu' : 1,
      'min_version': '15.02.330.0',
      'fixed_version': '15.02.330.9',
      'kb': '4509408'
  },
  {
    'product' : '2019',
    'cu' : 2,
    'min_version': '15.02.397.0',
    'fixed_version': '15.02.397.5',
    'kb': '4509408'
  }

];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS19-06',
  constraints:constraints,
  severity:SECURITY_WARNING
);