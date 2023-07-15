#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138900);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2013-3245", "CVE-2013-4388");
  script_bugtraq_id(61032, 62724);

  script_name(english:"VLC < 2.0.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote Windows host is prior to 2.0.8. It is, therefore, affected by 
multiple vulnerabilities:

  - An exploitable denial of service vulnerability exists in plugins/demux/libmkv_plugin.dll in VideoLAN VLC 
    Media Player 2.0.7 and possibly other versions. Allows remote attackers to cause a denial of service 
    (crash) and possibly execute arbitrary code via a crafted MKV file, possibly involving an integer 
    overflow and out-of-bounds read or heap-based buffer overflow, or an uncaught exception. (CVE-2013-3245).

  - An exploitable denial of service vulnerability exists in the mp4a packetizer 
    (modules/packetizer/mpeg4audio.c) in VideoLAN VLC Media Player before 2.0.8. Allows remote attackers to 
    cause a denial of service (crash) and possibly execute arbitrary code via unspecified vectors. 
    (CVE-2013-4388).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2013/Jul/71");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/developers/vlc-branch/NEWS");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.0.8 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3245");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl", "macosx_vlc_installed.nbin");

  exit(0);
}

include('vcf.inc');

os = get_kb_item('Host/MacOSX/Version');

if (!isnull(os))
    app = 'VLC';
else
    app = 'VLC media player';

app_info = vcf::get_app_info(app:app);
constraints = [{'fixed_version':'2.0.8'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
 