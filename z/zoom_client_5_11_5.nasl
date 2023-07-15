##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(164143);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-28756");

  script_name(english:"Zoom Client 5.7.3 < 5.11.5 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the Zoom Client installed on the remote host is between 5.7.3 and 5.11.5. It is, therefore, affected by
a privilege escalation vulnerability in the auto-update process. A local low-privileged user could exploit this 
vulnerability to escalate their privileges to root.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://explore.zoom.us/en/trust/security/security-bulletin/?filter-cve=CVE-2022-28756
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02d60d68");
  # https://support.zoom.us/hc/en-us/articles/201361963-Release-notes-for-macOS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f673050");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 5.11.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28756");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_zoom_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info =  vcf::get_app_info(app:'zoom');

var constraints = [{ 'min_version' : '5.7.3', 'fixed_version' : '5.11.5' }];

vcf::check_granularity(app_info:app_info, sig_segments:3);

vcf::check_all_backporting(app_info:app_info);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);