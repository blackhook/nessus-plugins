#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(97744);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2017-0110");
  script_bugtraq_id(96621);
  script_xref(name:"MSFT", value:"MS17-015");
  script_xref(name:"MSKB", value:"4012178");

  script_name(english:"MS17-015: Security Update for Microsoft Exchange Server (4013242)");
  script_summary(english:"Checks the version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Microsoft Exchange Server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft Exchange Server is missing a security update. It
is, therefore, affected by an elevation of privilege vulnerability in
Outlook Web Access (OWA) due to improper handling of web requests. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted email containing a malicious link or attachment, to
execute arbitrary script code, inject content, or disclose sensitive
information.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?923bc27d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange Server 2013 and
2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0110");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

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
    'product': '2013',
    'cu': '14',
    'kb': '4012178',
    'min_version': '15.00.1236.0',
    'fixed_version': '15.00.1236.6'
  },
  {
    'product' : '2013',
    'cu': '4',
    'kb': '4012178',
    'min_version': '15.00.847.0',
    'fixed_version': '15.00.847.53'
  },
  {
    'product': '2016',
    'cu': '3',
    'kb': '4012178',
    'min_version': '15.01.544.0',
    'fixed_version': '15.01.544.30'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS17-015',
  constraints:constraints,
  severity:SECURITY_WARNING
);
