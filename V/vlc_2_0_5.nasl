#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63381);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/24");

  script_cve_id("CVE-2012-5855", "CVE-2013-1868");
  script_bugtraq_id(57079, 56405);

  script_name(english:"VLC < 2.0.5 Multiple Vulnerabilities");

   script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote Windows host is prior to 2.0.5. It is, therefore, 
affected by multiple vulnerabilities:

  - An exploitable denial of service vulnerability exists in the SHAddToRecentDocs function in VideoLAN VLC 
    media player before 2.0.5. Allow user-assisted attackers to cause a denial of service (crash) via a 
    crafted file name that triggers an incorrect string-length calculation when the file is added to VLC. 
    (CVE-2012-5855).

  - Multiple buffer overflows in VideoLAN VLC media player before 2.0.5. Allow remote attackers to cause a 
    denial of service (crash) and execute arbitrary code via vectors related to the (1) freetype renderer 
    and (2) HTML subtitle parser. (CVE-2013-1868).
 
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported 
version number.");
  script_set_attribute(attribute:"see_also", value:"https://securitytracker.com/id/1027929");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/security/sa1301.html");
  # http://git.videolan.org/?p=vlc/vlc-2.0.git;a=commitdiff;h=8e8b02ff1720eb46dabe2864e79d47b40a2792d5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cd2e15e");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.0.5.html");
  # https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A16781
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d7f40a0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1868");
  
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/04");

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
constraints = [{'fixed_version':'2.0.5'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
 