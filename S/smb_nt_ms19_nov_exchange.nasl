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
  script_id(131025);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/04");

  script_cve_id("CVE-2019-1373");
  script_xref(name:"MSKB", value:"4523171");
  script_xref(name:"MSFT", value:"MS19-4523171");

  script_name(english:"Security Updates for Exchange (November 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft Exchange through the deserialization of
    metadata via PowerShell. An attacker who successfully
    exploited the vulnerability could run arbitrary code in
    the context of the logged in user. Exploitation of this
    vulnerability requires that a user run cmdlets via
    PowerShell. The security update addresses the
    vulnerability by correcting how Exchange serializes its
    metadata. (CVE-2019-1373)");
  # https://support.microsoft.com/en-us/help/4523171/security-update-for-exchange-server-2019-2016-and-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a817f0c6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4523171 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/15");

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
    'product' : '2013',
    'cu' : 23,
    'min_version': '15.00.1497.0',
    'fixed_version': '15.00.1497.4',
    'kb': '4523171'
  },
   {
    'product' : '2016',
    'cu' : 13,
    'min_version': '15.01.1779.0',
    'fixed_version': '15.01.1779.7',
    'kb': '4523171'
  },
  {
    'product' : '2016',
    'cu' : 14,
    'min_version': '15.01.1847.0',
    'fixed_version': '15.01.1847.5',
    'kb': '4523171'
  },
  {
    'product' : '2019',
    'cu' : 2,
    'min_version': '15.02.397.0',
    'fixed_version': '15.02.397.9',
    'kb': '4523171'
  },
  {
    'product' : '2019',
    'cu' : 3,
    'min_version': '15.02.464.0',
    'fixed_version': '15.02.464.7',
    'kb': '4523171'
  }

];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS19-09',
  constraints:constraints,
  severity:SECURITY_WARNING
);