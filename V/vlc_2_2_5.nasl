#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100592);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/12");

  script_cve_id(
    "CVE-2017-8310",
    "CVE-2017-8311",
    "CVE-2017-8313",
    "CVE-2017-9300",
    "CVE-2017-9301"
  ); 
  script_bugtraq_id(98746, 98747, 98633, 98634, 98638);

  script_name(english:"VLC Media Player < 2.2.5 Multiple Vulnerabilities");
  script_summary(english:"Checks the VLC media player version.");

  script_set_attribute(attribute:"synopsis", value:
"A media player installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is prior
to 2.2.5. It is, therefore, affected by the multiple vulnerabilities :

  - A denial of service vulnerability exists within file plugins\audio_filter\libmpgatofixed32_plugin.dll when
    parsing media files due to improper validation of user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted file, to crash the application. (CVE-2017-9301)

  - A flaw exists, related to a ParseJSS null skip, when handling specially crafted subtitle files downloaded by
    the media player. An unauthenticated, remote attacker can exploit this, via a specially crafted file, to
    execute arbitrary code.

  - A heap-based buffer overflow condition exists due to improper validation of user-supplied input. An unauthenticated, 
    remote attacker can exploit this, via a specially crafted AVI file, to execute arbitrary code.

  - A memory corruption issue exists when handling LPCM in VOB files. An unauthenticated, remote attacker can
    exploit this, via a specially crafted file, to execute arbitrary code.
    
  - An exploitable vulnerability exists in plugins\codec\libflac_plugin.dll, allows remote attackers to cause 
    denial of service (heap corruption and application crash) or possibly have unspecified other impact via a crafted 
    FLAC file. (CVE-2017-9300). 

  - An exploitable Heap out-of-bound read vulnerability exists in ParseJSS of VideoLan VLC. This is due to missing check of 
    string termination allows attackers to read data beyond allocated memory and potentially crash the process via a crafted 
    subtitles file. (CVE-2017-8313).

  - An exploitable heap based buffer overflow vulnerability exists in ParseJSS of VideoLan VLC. This is due to skipping NULL 
    terminator in an input string allows attackers to execute arbitrary code via a crafted subtitles file. (CVE-2017-8311).

  - An exploitable Heap out-of-bound read vulnerability exists in CreateHtmlSubtitle of VideoLan VLC. This is due to missing 
    check of string termination allows attackers to read data beyond allocated memory and potentially crash the process 
    (causing a denial of service) via a crafted subtitles file. (CVE-2017-8310).");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/developers/vlc-branch/NEWS");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/releases/2.2.5.html");
  script_set_attribute(attribute:"see_also", value:"https://trac.videolan.org/vlc/ticket/17448");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/zeroday/FG-VD-16-067");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/zeroday/FG-VD-16-090");
  # https://www.engadget.com/2017/05/24/security-flaw-in-media-player-subtitles/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?472b5bc4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("installed_sw/VLC media player");

  exit(0);
}

include("vcf.inc");

app_name = "VLC media player";

app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

constraints = [{"fixed_version":"2.2.5"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
