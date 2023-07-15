#%NASL_MIN_LEVEL 70300
##
# Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158759);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/15");

  script_cve_id("CVE-2022-21990", "CVE-2022-24503");
  script_xref(name:"IAVA", value:"2022-A-0111-S");
  script_xref(name:"IAVA", value:"2022-A-0112-S");

  script_name(english:"Remote Desktop client for Windows Multiple Vulnerabilities (March 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows Remote Desktop client for Windows installed on the remote host is missing security updates. It is, therefore,
affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-21990)

  - An information disclosure vulnerability An authenticated, remote attacker can exploit this, via [VECTOR],
    to read small portions of heap memory. (CVE-2022-24503)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21990
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ca1f8f1");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-24503
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?51f17db8");
  # https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/clients/windowsdesktop-whatsnew
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbd96878");
  script_set_attribute(attribute:"solution", value:
"Upgrade to client version 1.2.2925 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21990");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
    { 'fixed_version' : '1.2.2925' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
