#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158168);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/22");

  script_cve_id("CVE-2021-34423", "CVE-2021-34424");

  script_name(english:"Zoom Client < 5.8.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the Zoom Client installed on the remote host is prior to 5.8.4. It is, therefore, affected by the
following vulnerabilities:

  - An unspecified buffer overflow condition. An unauthenticated, remote attacker can exploit this to cause a
    denial of service condition or the execution of arbitrary code. (CVE-2021-34423)

  - An unspecified information disclosure vulnerability. An unauthenticated, remote attacker can exploit this
    to disclose potentially sensitive information. (CVE-2021-34424)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://explore.zoom.us/en/trust/security/security-bulletin");
  script_set_attribute(attribute:"see_also", value:"https://support.zoom.us/hc/en-us/articles/201361953");
  script_set_attribute(attribute:"see_also", value:"https://support.zoom.us/hc/en-us/articles/201361963");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 5.8.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34423");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin", "macosx_zoom_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for Meetings", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

var app_info = NULL;

if (get_kb_item('installed_sw/Zoom Client for Meetings'))
  app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'zoom');

constraints = [{ 'fixed_version' : '5.8.4' }];

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_all_backporting(app_info:app_info);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

