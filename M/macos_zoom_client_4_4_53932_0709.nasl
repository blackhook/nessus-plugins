#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126590);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2019-13449", "CVE-2019-13450", "CVE-2019-13567");
  script_bugtraq_id(109082);
  script_xref(name:"CEA-ID", value:"CEA-2019-0540");

  script_name(english:"Zoom Client for Meetings 4.x < 4.4.53932.0709 Multiple Vulnerabilities (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a webcam hijack vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote macOS host is 4.x prior to 4.4.53932.0709. It is,
therefore, affected by multiple vulnerabilities. 

  - A denial of service vulnerability exists in Zoom due to an issue with the local webserver. An
    unauthenticated, remote attacker can exploit this issue, by convincing a user to click on a crafted link,
    to cause continual focus grabs and cause the application to stop responding. (CVE_2020-13449)

  - A webcam hijacking vulnerability exists in Zoom due to websites being able to interact with the Zoom
    webserver on localhost ports 19421 and 19424. An unauthenticated, remote attacker can exploit this, by
    convincing a user to visit an attacker controlled website, to force a user to join an attacker controlled
    video call with their video camera active. (CVE-2020-13450)
    
  - A remote code execution vulnerability exists in the Zoom Client due to a bug with the ZoomOpener daemon.
    An authenticated, remote attacker can exploit this, by convincing a user to visit a maliciously crafted
    launch URL, to execute arbitrary commands. (CVE-2019-13567)
    
Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  # https://medium.com/bugbountywriteup/zoom-zero-day-4-million-webcams-maybe-an-rce-just-get-them-to-visit-your-website-ac75c83f4ef5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43720b3e");
  # https://blog.zoom.us/wordpress/2019/07/08/response-to-video-on-concern/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1394c56f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 4.4.53932.0709 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13567");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:zoom:zoom_client_for_meetings");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_zoom_installed.nbin");
  script_require_keys("Host/MacOSX/Version", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/MacOSX/Version');

app_info = vcf::get_app_info(app:'zoom');

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '4', 'fixed_version' : '4.4.53932.0709' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
