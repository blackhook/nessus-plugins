#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105294);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-10699");

  script_name(english:"VLC Media Player < 2.2.7 Overflow Condition");
  script_summary(english:"Checks the VLC media player version.");

  script_set_attribute(attribute:"synopsis", value:
"A media player installed on the remote host is affected by an overflow condition.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is prior
to 2.2.7. It is, therefore, affected by an overflow condition in the lavc_GetVideoFormat() 
function in modules/codec/avcodec/video.c.
This vulnerability can cause a denial of service and potentially allow remote code execution.");
  script_set_attribute(attribute:"see_also", value:"https://trac.videolan.org/vlc/ticket/18467#no1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.2.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("installed_sw/VLC media player");

  exit(0);
}

include("vcf.inc");

app_name = "VLC media player";

app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

constraints = [{"fixed_version":"2.2.7"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
