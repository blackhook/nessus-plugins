##
# Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160941);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/19");

  script_cve_id("CVE-2022-22015", "CVE-2022-22017", "CVE-2022-26940");

  script_name(english:"Remote Desktop client for Windows Multiple Vulnerabilities (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows Remote Desktop client for Windows installed on the remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities:

  - An information disclosure vulnerability. An attacker can
  exploit this to disclose potentially sensitive
  information. (CVE-2022-22015, CVE-2022-26940)

  - A remote code execution vulnerability. An attacker can
  exploit this to bypass authentication and execute
  unauthorized arbitrary commands. (CVE-2022-22017)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ca553d7");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-22015
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54fabd57");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26940
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e279d0d7");
  # https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/windowsdesktop-whatsnew
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbd96878");
  script_set_attribute(attribute:"solution", value:
"Upgrade to client version 1.2.3130 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22017");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("remote_desktop_installed.nbin");
  script_require_keys("installed_sw/Microsoft Remote Desktop");

  exit(0);
}

include('vcf.inc');

var appname = "Microsoft Remote Desktop";

var app_info = vcf::get_app_info(app:appname, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '1.2.3130' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
