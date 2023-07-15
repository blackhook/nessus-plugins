#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177633);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2022-39952");

  script_name(english:"FortiNAC - External Control of File Name or Path in keyUpload scriptlet (FG-IR-22-300)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fortinet FortiNAC host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiNAC installed on the remote host is 8.3.x, 8.5.x, 8.6.x, 8.7.x, 8.8.x, 9.1.x prior to
9.1.8, 9.2.x prior to 9.2.6, or 9.4.x prior to 9.4.1. It is, therefore, affected by an external control of file name or
path security issue. An unauthenticated, remote attacker can exploit this, via a specially crafted HTTP request, to
execute unauthorized code or commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-300");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FortiNAC versions 9.1.8, 9.2.6, 9.4.1, or later, or upgrade to FortiNAC F version 7.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-39952");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Fortinet FortiNAC keyUpload.jsp arbitrary file write');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:fortinac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("fortinet_fortinac_web_detect.nbin");
  script_require_keys("installed_sw/Fortinet FortiNAC");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Fortinet FortiNAC');

var fixed_display = '9.1.8 / 9.2.6 / 9.4.1';
var constraints = [
  { 'min_version' : '8.3', 'max_version' : '8.3.999', 'fixed_display' : fixed_display},
  { 'min_version' : '8.5', 'max_version' : '8.5.999', 'fixed_display' : fixed_display},
  { 'min_version' : '8.6', 'max_version' : '8.6.999', 'fixed_display' : fixed_display},
  { 'min_version' : '8.7', 'max_version' : '8.7.999', 'fixed_display' : fixed_display},
  { 'min_version' : '8.8', 'max_version' : '8.8.999', 'fixed_display' : fixed_display},
  { 'min_version' : '9.1', 'fixed_version' : '9.1.8' },
  { 'min_version' : '9.2', 'fixed_version' : '9.2.6' },
  { 'min_version' : '9.4', 'fixed_version' : '9.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
