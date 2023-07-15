#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137753);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2014-9597", "CVE-2014-9598");
  script_bugtraq_id(72105, 72106);

  script_name(english:"VLC < 2.1.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote Windows host is prior to 2.1.6. It is, therefore, affected by 
multiple vulnerabilities:

  - An exploitable denial of service vulnerability exists in the picture_pool_Delete function in 
    misc/picture_pool.c in VideoLAN VLC media player 2.1.5. Allows remote attackers to execute arbitrary 
    code or cause a denial of service (DEP violation and application crash) via a crafted FLV file. 
    (CVE-2014-9597).

  - An exploitable denial of service vulnerability exists in the picture_Release function in misc/picture.c 
    in VideoLAN VLC media player 2.1.5. Allows remote attackers to execute arbitrary code or cause a denial 
    of service (write access violation) via a crafted M2V file. (CVE-2014-9598).");
  script_set_attribute(attribute:"see_also", value:"https://trac.videolan.org/vlc/ticket/13389");
  script_set_attribute(attribute:"see_also", value:"https://trac.videolan.org/vlc/ticket/13390");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.1.6 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9597");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/24");

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

if (os =~ 'Mac')
    app = 'VLC';
else
    app = 'VLC media player';

app_info = vcf::get_app_info(app:app);
constraints = [{'fixed_version':'2.1.6'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
