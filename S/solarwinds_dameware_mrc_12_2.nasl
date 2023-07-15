#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154473);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/29");

  script_cve_id("CVE-2021-31217");
  script_xref(name:"IAVA", value:"2021-A-0500");

  script_name(english:"SolarWinds DameWare Mini Remote Control < 12.2 Arbitrary File Deletion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a remote management application that is affected by an arbitrary file deletion vulnerability.");
  script_set_attribute(attribute:"description", value:
"An arbitrary file deletion vulnerability exists in Dameware Mini Remote Control Service due to insecure folder
permissions. An unauthenticated, remote attacker can exploit this by initiating a repair via the windows installer,
to delete arbitrary files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://documentation.solarwinds.com/en/success_center/dameware/content/release_notes/dameware_12-2_release_notes.htm#
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29aa68a9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds DameWare Mini Remote Control v12.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-31217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:dameware_mini_remote_control");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_dameware_mini_remote_control_installed.nbin");
  script_require_keys("installed_sw/SolarWinds DameWare Mini Remote Control");

  exit(0);
}

include('vcf.inc');

var app = vcf::get_app_info(app:'SolarWinds DameWare Mini Remote Control', win_local:TRUE);

var constraints = [{'fixed_version' : '12.2'}];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_HOLE, strict:FALSE);

