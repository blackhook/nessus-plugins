#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(112216);
  script_version("1.6");
  script_cvs_date("Date: 2019/04/05 23:25:09");

  script_cve_id("CVE-2018-11529");

  script_name(english:"VLC Media Player <= 2.2.8 Use-After-Free RCE");
  script_summary(english:"Checks the VLC media player version.");

  script_set_attribute(attribute:"synopsis", value:
"A media player installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is equal
or prior to 2.2.8. It is, therefore, affected by a use-after-free
vulnerability. An attacker could leverage this vulnerability to cause
a denial of service or potentially execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2018/Jul/28");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VLC version 3.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11529");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'VLC Media Player MKV Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("installed_sw/VLC media player");

  exit(0);
}

include("vcf.inc");

app_name = "VLC media player";

app_info = vcf::get_app_info(app:app_name, win_local:TRUE);

constraints = [{"min_version":"2.2.0", "max_version":"2.2.8", "fixed_version":"3.0.3"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
