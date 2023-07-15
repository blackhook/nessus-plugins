#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136895);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2018-19857");
  script_bugtraq_id(106130);

  script_name(english:"VLC < 3.0.5 Denial of Service and/or Infoleak Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by denial of service and/or a potential infoleak vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host with version 3.0.4.  It is, therefore, affected 
by a denial of service and/or a potential infoleak vulnerability. (CVE-2018-19857).");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/bid/106130");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 3.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19857");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version", "installed_sw/VLC media player");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'VLC media player', win_local:TRUE);

constraints = [{'fixed_version':'3.0.5'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
