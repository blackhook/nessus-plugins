#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(70560);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/29");

  script_cve_id("CVE-2013-4388", "CVE-2013-6283");
  script_bugtraq_id(61844, 62724);

  script_name(english:"VLC < 2.0.9 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"An exploitable denial of service vulnerability exists in VideoLAN VLC Media Player 2.0.8 and earlier. Allows remote attackers to cause a denial of service (crash) and possibly execute arbitrary code via a long string in a URL in a m3u file.");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/27700");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.0.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6283");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
constraints = [{'fixed_version':'2.0.9'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
 
