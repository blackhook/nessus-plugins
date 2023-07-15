#%NASL_MIN_LEVEL 80900
##
# Tenable, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(177353);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-33144");
  script_xref(name:"IAVA", value:"2023-A-0299");

  script_name(english:"Security Update for Microsoft Visual Studio Code (June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Visual Studio Code installed on the remote Windows host is prior to 1.79.1. It is, therefore,
affected by a session spoofing vulnerability. An attacker can exploit this to perform actions with the privileges of
another user.");
  script_set_attribute(attribute:"see_also", value:"https://code.visualstudio.com/updates/v1_79");
  script_set_attribute(attribute:"solution", value:
"Upgrade to  Microsoft Visual Studio Code 1.79.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33144");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_visual_studio_code_installed.nbin", "microsoft_visual_studio_code_win_user_installed.nbin");
  script_require_keys("installed_sw/Microsoft Visual Studio Code", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Microsoft Visual Studio Code', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '1.79.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
