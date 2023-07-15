#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174260);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/15");

  script_cve_id("CVE-2022-42470");
  script_xref(name:"IAVA", value:"2023-A-0198-S");

  script_name(english:"Fortinet FortiClient - Arbitrary file creation by unprivileged users (FG-IR-22-320)");

  script_set_attribute(attribute:"synopsis", value:
"remote Windows host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FortiClient installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the FG-IR-22-320 advisory.

  - A relative path traversal vulnerability in Fortinet FortiClient (Windows) 7.0.0 - 7.0.7, 6.4.0 - 6.4.9,
    6.2.0 - 6.2.9 and 6.0.0 - 6.0.10 allows an attacker to execute unauthorized code or commands via sending a
    crafted request to a specific named pipe. (CVE-2022-42470)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-22-320");
  script_set_attribute(attribute:"solution", value:
"Please upgrade to FortiClientWindows version 7.2.0 or above 
Please upgrade to FortiClientWindows version 7.0.8 or above");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-42470");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient");

  exit(0);
}

include('vcf.inc');

var app_name = 'FortiClient';
var app_info = vcf::get_app_info(app:app_name);

var constraints = [
  { 'min_version' : '6.0.0', 'max_version' : '6.0.10', 'fixed_display' : '7.0.8' },
  { 'min_version' : '6.2.0', 'max_version' : '6.2.9', 'fixed_display' : '7.0.8' },
  { 'min_version' : '6.4.0', 'max_version' : '6.4.9', 'fixed_display' : '7.0.8' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
