#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135189);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2020-11469", "CVE-2020-11470");

  script_name(english:"Zoom Client for Meetings < 4.6.9.19273.0402 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote macOS or Mac OS X host is prior to 4.6.9.19273.0402 and
is therefore affected by multiple vulnerabilities.

  - A privilege escalation vulnerability exists in the Zoom client due to a 'runwithroot' file being placed in
    a user-writable directory. An unauthenticated, local attacker can exploit this, by replacing the
    'runwithroot' file, to obtain root access. (CVE-2020-11469)

  - A vulnerability exists in the Zoom client due to the use of the disable-library-validation entitlement. An
    authenticated, local attacker can exploit this, by loading a crafted library, to obtain unprompted camera
    and microphone access. (CVE-2020-11470)

  - Access Control Bypass: A remote authenticated attacker could gain access to the chat in a webinar when the
    chat has been disabled.

Note that Nessus has not tested for these issues but has instead relied only on the application's
self-reported version number.");
  # https://support.zoom.us/hc/en-us/articles/201361963-New-Updates-for-macOS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b6b36501");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 4.6.9.19273.0402 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11469");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zoom:zoom_client_for_meetings");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom_cloud_for_meetings");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_zoom_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'zoom');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '0.0', 'fixed_version' : '4.6.9 (19273.0402)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);




