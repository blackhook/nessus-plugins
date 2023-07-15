#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147024);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-26857");
  script_xref(name:"MSKB", value:"5000978");
  script_xref(name:"MSFT", value:"MS21-5000978");
  script_xref(name:"IAVA", value:"2021-A-0111-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/04/16");
  script_xref(name:"CISA-NCAS", value:"AA22-011A");
  script_xref(name:"CEA-ID", value:"CEA-2021-0014");
  script_xref(name:"CEA-ID", value:"CEA-2021-0018");
  script_xref(name:"CEA-ID", value:"CEA-2021-0013");

  script_name(english:"Security Update for Microsoft Exchange Server 2010 SP 3 (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Exchange Server installed on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Server installed on the remote host
is missing a security update. It is, therefore, affected by
a vulnerability:

  - A remote code execution vulnerability. An attacker could exploit this to
  execute unauthorized arbitrary code. (CVE-2021-26857)");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2010-service-pack-3-march-2-2021-kb5000978-894f27bf-281e-44f8-b9ba-dad705534459
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75b72573");
  # https://msrc-blog.microsoft.com/2021/03/02/multiple-security-updates-released-for-exchange-server/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fedb98e4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security update to address this issue:
  -KB5000978");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26857");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    'product' : '2010',
    'min_version': '14.3.0.0',
    'fixed_version': '14.03.513.0'
  }
];

vcf::microsoft::exchange::check_version_and_report
(
  app_info:app_info,
  bulletin:'MS21-03',
  constraints:constraints,
  severity:SECURITY_WARNING
);