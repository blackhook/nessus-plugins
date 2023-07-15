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
  script_id(134376);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2020-0903");
  script_xref(name:"MSKB", value:"4540123");
  script_xref(name:"MSFT", value:"MS20-4540123");
  script_xref(name:"IAVA", value:"2020-A-0090-S");

  script_name(english:"Security Updates for Exchange (March 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

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
    properly sanitizes web requests. (CVE-2020-0903)");
  # https://support.microsoft.com/en-us/help/4540123/security-update-for-exchange-server-2019-and-2016
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c6ea048");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4540123 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0903");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/10");

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
    'unsupported_cu': 13,
    'cu' : 14,
    'min_version': '15.01.1847.0',
    'fixed_version': '15.01.1847.10',
    'kb': '4540123'
  },
  {
    'product' : '2016',
    'unsupported_cu' : 13,
    'cu' : 15,
    'min_version': '15.01.1913.0',
    'fixed_version': '15.01.1913.10',
    'kb': '4540123'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 2,
    'cu' : 3,
    'min_version': '15.02.464.0',
    'fixed_version': '15.02.464.14',
    'kb': '4540123'
  },
  {
    'product' : '2019',
    'unsupported_cu' : 2,
    'cu' : 4,
    'min_version': '15.02.529.0',
    'fixed_version': '15.02.529.11',
    'kb': '4540123'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS20-03',
  constraints:constraints,
  severity:SECURITY_WARNING
);
