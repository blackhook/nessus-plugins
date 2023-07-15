#
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138342);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/10/25");

  script_cve_id("CVE-2014-9743", "CVE-2016-3941");
  script_bugtraq_id(79961, 85752);

  script_name(english:"VLC < 2.2.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote Windows host is prior to 2.2.0. It is, therefore, affected by 
multiple vulnerabilities:

  - An exploitable Cross-site scripting (XSS) vulnerability exists in the httpd_HtmlError function in 
    network/httpd.c in the web interface in VideoLAN VLC Media Player before 2.2.0 allows remote attackers to
    inject arbitrary web script or HTML via the path info. (CVE-2014-9743).

  - An exploitable denial of service vulnerability exists in the AStreamPeekStream function in input/stream.c 
    in VideoLAN VLC media player before 2.2.0. Allows remote attackers to cause a denial of service (crash) 
    via a crafted wav file, related to seek across EOF. (CVE-2016-3941).");
  # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3941
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e32b7fa2");
  script_set_attribute(attribute:"see_also", value:"https://www.securitytracker.com/id/1035456");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.2.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9743");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/09");

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
constraints = [{'fixed_version':'2.2.0'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);