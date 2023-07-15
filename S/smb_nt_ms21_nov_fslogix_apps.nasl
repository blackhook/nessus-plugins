#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154985);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/19");

  script_cve_id("CVE-2021-41373");
  script_xref(name:"IAVA", value:"2021-A-0558");

  script_name(english:"Security Updates for Microsoft FSLogix Apps (November 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft FSLogix Apps installation is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft FSLogix Apps installation on the remote host is missing security updates. It is, therefore,
affected by an information disclosure vulnerability. A local attacker may use this vulnerability to
disclose user data redirected to the profile or Office container via FSLogix Cloud cache. This data can
include user profile settings and files. Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://docs.microsoft.com/en-us/fslogix/whats-new#fslogix-2105-hf_01-29797962170
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7cfe2a40");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate update referenced in the Microsoft advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41373");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:fslogix_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_fslogix_installed.nbin");
  script_require_keys("installed_sw/Microsoft FSLogix Apps");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft FSLogix Apps';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '2.9.7979.62170' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
