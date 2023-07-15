#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(48760);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/22");

  script_cve_id(
    "CVE-2010-1441",
    "CVE-2010-1442",
    "CVE-2010-1443",
    "CVE-2010-1444",
    "CVE-2010-1445",
    "CVE-2011-1087"
  );
  script_bugtraq_id(
    38569,
    39620,
    41398,
    78973,
    78975,
    78978,
    78990,
    79000
  );

  script_name(english:"VLC Media Player < 1.0.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote Windows host is prior to 1.0.6. It is, therefore, 
affected by multiple vulnerabilities:

  - A denial of service (DoS) vulnerability exists in VideoLAN VLC media player before 1.0.6 due to 
    heap-based buffer overflow. An unauthenticated, remote attacker can exploit this issue, via a crafted 
    byte stream to the (1) A/52, (2) DTS, or (3) MPEG Audio decoder, to cause a denial of service 
    (application crash) or possibly execute arbitrary code. (CVE-2010-1441).

  - A denial of service (DoS) vulnerability exists in VideoLAN VLC media player before 1.0.6. 
    An unauthenticated, remote attacker can exploit this issue, via a crafted byte stream to the (1) AVI, 
    (2) ASF, or (3) Matroska (aka MKV) demuxer, to cause a denial of service (invalid memory access and 
    application crash) or possibly execute arbitrary code. (CVE-2010-1442).

  - A denial of service (DoS) vulnerability exists in VideoLAN VLC media player before 1.0.6 due to 
    parse_track_node function in modules/demux/playlist/xspf.c in the XSPF playlist parser. 
    An unauthenticated, remote attacker can exploit this issue, via an empty location element in an XML 
    Shareable Playlist Format (XSPF) document, to cause a denial of service (NULL pointer dereference and 
    application crash). (CVE-2010-1443).

  - A denial of service (DoS) vulnerability exists in VideoLAN VLC media player before 1.0.6 due to 
    ZIP archive decompressor. An unauthenticated, remote attacker can exploit this issue, via a crafted 
    archive, to ccause a denial of service (invalid memory access and application crash) or possibly execute 
    arbitrary code. (CVE-2010-1444).

  - A denial of service (DoS) vulnerability exists in VideoLAN VLC media player before 1.0.6 due to 
    heap-based buffer overflow. An unauthenticated, remote attacker can exploit this issue,  via a crafted 
    byte stream in an RTMP session, to cause a denial of service (application crash) or possibly execute 
    arbitrary code. (CVE-2010-1445).

  - A denial of service (DoS) vulnerability exists in VideoLAN VLC media player before 1.0.6 due to 
    buffer overflow. An user-assisted, remote attacker can exploit this issue, via a crafted .mp3 file that 
    is played during bookmark creation, to cause a denial of service (memory corruption and 
    application crash) or possibly execute arbitrary code. (CVE-2011-1087).

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.zeroscience.mk/en/vulnerabilities/ZSL-2010-4931.php
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?066ea8f5");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/security/sa1003.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 1.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1087");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
constraints = [{'fixed_version':'1.0.6'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
