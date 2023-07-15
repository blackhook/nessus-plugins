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
  script_id(141931);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-17023");
  script_xref(name:"IAVA", value:"2020-A-0459-S");

  script_name(english:"Security Update for Microsoft Visual Studio Code (CVE-2020-17023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Visual Studio Code installed on the remote
Windows host is prior to 1.50.1. It is, therefore, affected by the
following vulnerability:

  - A remote code execution vulnerability exists in Visual Studio Code when a
  user is tricked into opening a malicious 'package.json' file. An attacker who
  successfully exploited the vulnerability could run arbitrary code in the
  context of the current user. If the current user is logged on with
  administrative user rights, an attacker could take control of the affected
  system. An attacker could then install programs; view, change, or delete
  data; or create new accounts with full user rights. To exploit this
  vulnerability, an attacker would need to convince a target to clone a
  repository and open it in Visual Studio Code. Attacker-specified code would
  execute when the target opens the malicious 'package.json' file.
  (CVE-2020-17023)");
  script_set_attribute(attribute:"see_also", value:"https://code.visualstudio.com/updates/v1_50");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-17023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b0953a5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to  Microsoft Visual Studio Code 1.50.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17023");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_code_installed.nbin", "microsoft_visual_studio_code_win_user_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio Code", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Microsoft Visual Studio Code', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '1.50.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);



