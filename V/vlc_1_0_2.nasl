#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(41626);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2011-3623");
  script_bugtraq_id(36439, 79751);
  script_xref(name:"Secunia", value:"36762");

  script_name(english:"VLC Media Player < 1.0.2 Stack-based Buffer Overflow");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by stack-based buffer overflow.");
  script_set_attribute(attribute:"description", value:
"A stack-based buffer overflow condition exists in VLC media player before 1.0.2 due (1) a crafted ASF file, 
related to the ASF_ObjectDumpDebug function in modules/demux/asf/libasf.c; (2) a crafted AVI file,related to 
the AVI_ChunkDumpDebug_level function in modules/demux/avi/libavi.c; or (3) a crafted MP4 file, related to 
the __MP4_BoxDumpStructure function in modules/demux/mp4/libmp4.c. An unauthenticated, remote attacker can 
exploit this, via tricking a user into opening a specially crafted MP4, ASF, or AVI file, to cause execution 
of arbitrary code with the user's privileges.
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/security/sa0901.html");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/285370");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 1.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3623");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
constraints = [{'fixed_version':'1.0.2'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);