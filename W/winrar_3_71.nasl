#%NASL_MIN_LEVEL 70300
#
#  (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31641);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_xref(name:"SECUNIA", value:"29407");

  script_name(english:"WinRAR < 3.71 Archive Handling Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running WinRAR, an archive manager for Windows.

The version of WinRAR installed on the remote host reportedly is
affected by several heap corruption and stack-based buffer overflow
vulnerabilities. If an attacker can trick a user on the affected host
into opening a specially crafted archive using the affected
application, this method could be used to execute arbitrary code on
the affected system subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://www.viestintavirasto.fi/en/cybersecurity.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WinRAR 3.71 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on in depth analysis of the vendor advisory by Tenable");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rarlab:winrar");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("winrar_win_installed.nbin");
  script_require_keys("installed_sw/RARLAB WinRAR", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'RARLAB WinRAR', win_local:TRUE);

constraints = [
  { 'fixed_version' : '3.71' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
