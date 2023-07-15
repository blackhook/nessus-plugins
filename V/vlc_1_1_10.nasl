#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55024);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/09");

  script_cve_id("CVE-2011-1931", "CVE-2011-2194");
  script_bugtraq_id(47602, 48171);

  script_xref(name:"EDB-ID", value:"17372");
  script_xref(name:"Secunia", value:"44412");

  script_name(english:"VLC < 1.1.10 Multiple Vulnerabilities");

   script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote Windows host is prior to 1.1.10. It is, therefore, 
affected by multiple vulnerabilities:

  - A denial of service (DoS) vulnerability exists in VideoLAN VLC media player before 1.1.10. 
    An unauthenticated remote attacker can exploit this issue, via a malformed AMV file, to cause a denial of 
    service (memory corruption) or possibly execute arbitrary code. (CVE-2011-1931).

  - A denial of service (DoS) vulnerability exists in VideoLAN VLC media player before 1.1.10 due to integer 
    overflow in XSPF playlist parser. An unauthenticated remote attacker can exploit this issue, via 
    unspecified vectors that trigger a heap-based buffer overflow to cause a denial of service 
    (memory corruption) or possibly execute arbitrary code. (CVE-2011-2194).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cxsecurity.com/issue/WLB-2011070117");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/security/sa1104.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VLC version 1.1.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2194");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
constraints = [{'fixed_version':'1.1.10'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);