##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146102);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/08");

  script_cve_id("CVE-2020-26664");
  script_xref(name:"IAVB", value:"2021-B-0007");

  script_name(english:"VLC < 3.0.12 Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a media player that is affected by a heap-based buffer overflow condition.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is prior to 3.0.12. It is, therefore, affected by a
heap-based buffer overflow condition. A vulnerability in EbmlTypeDispatcher::send in VideoLAN VLC media player allows
attackers to trigger a heap-based buffer overflow via a crafted .mkv file.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/security/sb-vlc3012.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 3.0.12 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl", "macosx_vlc_installed.nbin");
  script_require_ports("installed_sw/VLC media player", "installed_sw/VLC");

  exit(0);
}

include('vcf.inc');

os = get_kb_item('Host/MacOSX/Version');
if (get_kb_item("SMB/Registry/Enumerated")) win_local = TRUE;

if (!isnull(os))
    app = 'VLC';
else
    app = 'VLC media player';

app_info = vcf::get_app_info(app:app, win_local:win_local);

constraints = [{'fixed_version':'3.0.12'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
