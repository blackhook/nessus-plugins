#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(101522);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2017-8559", "CVE-2017-8560", "CVE-2017-8621");
  script_bugtraq_id(99448, 99449, 99533);
  script_xref(name:"MSKB", value:"4018588");
  script_xref(name:"MSFT", value:"MS17-4018588");

  script_name(english:"KB4018588: Security Update for Microsoft Exchange Server");
  script_summary(english:"Checks the version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Microsoft Exchange Server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft Exchange Server is missing a security update. It
is, therefore, affected by multiple vulnerabilities :

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist in Microsoft Exchange Outlook Web Access (OWA)
    due to improper validation of user-supplied input in web
    requests. An unauthenticated, remote attacker can
    exploit these, via a specially crafted link, to execute
    arbitrary script code in a user's browser session.
    (CVE-2017-8559, CVE-2017-8560)

  - A cross-site redirection vulnerability exists due to
    improper validation of user-supplied input before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, by convincing a user to
    follow a link, to cause the user to load a malicious
    website, which then can be used to conduct further
    attacks. (CVE-2017-8621)");
  # https://support.microsoft.com/en-us/help/4018588/description-of-the-security-update-for-microsoft-exchange-july-11-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb2a7256");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange Server 2010,
2013, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8621");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/13");

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
    'product' : '2010',
    'kb': '4018588',
    'min_version': '14.03.361.0',
    'fixed_version': '14.03.361.1'
  },
  {
    'product' : '2013',
    'cu': '16',
    'kb': '4018588',
    'min_version': '15.00.1293.0',
    'fixed_version': '15.00.1293.4'
  },
  {
    'product': '2013',
    'cu': '4',
    'kb': '4018588',
    'min_version': '15.00.847.0',
    'fixed_version': '15.00.847.55'
  },
  {
    'product' : '2016',
    'cu': '5',
    'kb': '4018588',
    'min_version': '15.01.845.0',
    'fixed_version': '15.01.845.36'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS17-07',
  constraints:constraints,
  severity:SECURITY_WARNING
);