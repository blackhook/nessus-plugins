#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60049);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/24");

  script_cve_id("CVE-2012-2396", "CVE-2012-3377");
  script_bugtraq_id(53535, 54345);

  script_name(english:"VLC Media Player < 2.0.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is prior to 2.0.2. It is, therefore, affected 
by the following vulnerabilities :

  - A denial of service (DoS) vulnerability exists in libpng_plugin in VLC media player before 2.0.2. Allows 
    remote attackers to cause a denial of service (crash) via a crafted PNG file. (CVE-2012-2396)

  - A denial of service (DoS) vulnerability exists in the Ogg_DecodePacket function in the OGG demuxer 
    (modules/demux/ogg.c) in VideoLAN VLC media player before 2.0.2 . Allows remote attackers to cause a 
    denial of service (application crash) and possibly execute arbitrary code via a crafted OGG file. 
    (CVE-2012-3377)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.0.2.html");
  script_set_attribute(attribute:"see_also", value:"https://www.securitytracker.com/id?1027224");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/18757");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC Media Player version 2.0.2 or later.  Alternatively,
remove any affected plugin files from VLC's plugins directory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2396");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
constraints = [{'fixed_version':'2.0.2'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
 
