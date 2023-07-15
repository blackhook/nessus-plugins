#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165176);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-41031");

  script_name(english:"Fortinet FortiClient 6.2 <= 6.2.9 / 6.4.x < 6.4.6 / 7.x < 7.0.2 Path Traversal (FG-IR-21-190)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation.");
  script_set_attribute(attribute:"description", value:
"A relative path traversal vulnerability in FortiClient for Windows versions 7.0.2 and prior, 6.4.6 and prior and 6.2.9 
and below may allow a local unprivileged attacker to escalate their privileges to SYSTEM via the named pipe responsible 
for FortiESNAC service.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-190");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 6.4.7, 7.0.3, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41031");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FortiClient');

var constraints = [
  {'min_version' : '6.2', 'max_version' : '6.2.9', 'fixed_display' : '6.4.7 / 7.0.3'},
  {'min_version' : '6.4.0', 'fixed_version' : '6.4.7'},
  {'min_version' : '7.0.0', 'fixed_version' : '7.0.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
