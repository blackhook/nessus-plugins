#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136896);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-17670");
  script_bugtraq_id(102214);

  script_name(english:"VLC < 2.2.9 Type Conversion Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by type conversion vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is earlier than 2.2.9.  It is, therefore, affected 
by a type conversion vulnerability in modules/demux/mp4/libmp4.c in the MP4 demux module leading to a invalid free, 
because the type of a box may be changed between a read operation and a free operation.(CVE-2017-17670).");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/bid/102214");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.2.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/15");
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

constraints = [{'fixed_version':'2.2.9'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
