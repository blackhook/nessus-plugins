#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155789);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/24");

  script_cve_id("CVE-2021-42754");
  script_xref(name:"IAVA", value:"2021-A-0562-S");

  script_name(english:"Fortinet FortiClient 6.4.x < 6.4.6 / 7.x < 7.0.1 Dylib Injection (FG-IR-21-079) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote macOS host is affected by a Dylib injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote macOS host is running a version of Fortinet FortiClient that is 6.4.x prior to 6.4.6 or 7.x prior to 7.0.1.
It is, therefore, affected by a dylib injection vulnerability. An authenticated, local attacker can exploit this, by
replacing the FortiClient camera handling library with a malicious one, to hijack the macOS camera.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.fortiguard.com/psirt/FG-IR-21-079");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 6.4.6, 7.0.1, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42754");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient (macOS)");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'FortiClient (macOS)');

constraints = [
  {'min_version' : '6.4.0', 'fixed_version' : '6.4.6'},
  {'min_version' : '7.0.0', 'fixed_version' : '7.0.1'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
