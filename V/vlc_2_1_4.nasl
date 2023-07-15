#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137358);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id("CVE-2014-3441");
  script_bugtraq_id(67315);

  script_name(english:"VLC < 2.1.4 DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in VLC media player. An unauthenticated, remote attacker can exploit 
this issue, by tricking a user into opening a specially crafted .png file, to cause the application to stop responding.");
  # https://packetstormsecurity.com/files/126564/VLC-Player-2.1.3-Memory-Corruption.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fba8d459");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 2.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3441");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

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

constraints = [{'fixed_version':'2.1.4'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

