#%NASL_MIN_LEVEL 80900
##
# Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174112);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/10");

  script_cve_id("CVE-2023-28267");

  script_name(english:"Remote Desktop client for Windows Information Disclosure (April 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows Remote Desktop client for Windows installed on the remote host is missing security updates. It is, 
therefore, affected by an information disclosure vulnerability. This vulnerability could be triggered when a user
connects a Windows client to a malicious server. An attacker who successfully exploited this vulnerability could 
potentially read small portions of heap memory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-28267
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d2a7545");
  # https://learn.microsoft.com/en-us/azure/virtual-desktop/whats-new-client-windows#updates-for-version-124159
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e83d2a81");
  script_set_attribute(attribute:"solution", value:
"Upgrade to client version 1.2.4159 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28267");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("remote_desktop_installed.nbin");
  script_require_keys("installed_sw/Microsoft Remote Desktop");

  exit(0);
}

include('vcf.inc');

var appname = "Microsoft Remote Desktop";

var app_info = vcf::get_app_info(app:appname, win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
    { 'fixed_version' : '1.2.4159' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
