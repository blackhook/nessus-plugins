##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(162140);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/14");

  script_cve_id("CVE-2021-44169");

  script_name(english:"Fortinet FortiClient 6.0.x / 6.2.x / 6.4.x < 6.4.7 / 7.x < 7.0.1 Privilege Escalation (FG-IR-21-088)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient running on the remote host is affected by a privilege escalation vulnerability. An
unsafe search path vulnerability in FortiClien Windows 7.0.0, 6.4.6 and below, 6.2.x, and 6.0.x may allow an attacker to
perform a DLL Hijack attack on affected devices via a malicious OpenSSL engine library in the search path.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-088");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 6.4.7, 7.0.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/13");

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
  {'max_version' : '6.0.0', 'max_version' : '6.0.99999', 'fixed_display' : '6.4.7 / 7.0.1'},
  {'max_version' : '6.2.0', 'max_version' : '6.2.99999', 'fixed_display' : '6.4.7 / 7.0.1'},
  {'min_version' : '6.4.0', 'fixed_version' : '6.4.7'},
  {'min_version' : '7.0.0', 'fixed_version' : '7.0.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
