#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137397);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/17");

  script_cve_id("CVE-2015-5949");
  script_bugtraq_id(76448);

  script_name(english:"VLC < 2.2.2 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by denial of service and/or a potential infoleak 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in VLC media player before 2.2.2. Allows remote attackers to 
cause a denial of service (crash) and possibly execute arbitrary code via a crafted 3GP file, which triggers 
the freeing of arbitrary pointers.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # http://packetstormsecurity.com/files/133266/VLC-2.2.1-Arbitrary-Pointer-Dereference.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7e9c3ed");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5949");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version", "installed_sw/VLC media player");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'VLC media player', win_local:TRUE);

constraints = [{'fixed_version':'2.2.2'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
