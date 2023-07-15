#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135706);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/23");

  script_cve_id("CVE-2018-14333");

  script_name(english:"TeamViewer Exposure of Sensitive Information");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The version of TeamViewer installed on the remote Windows host upto 13.1.1548 stores a password 
in Unicode format within TeamViewer.exe process memory between '[00 88]' and '[00 00 00]' delimiters, 
which might make it easier for attackers to obtain sensitive information by leveraging an unattended 
workstation on which TeamViewer has disconnected but remains running.");
  # https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-14333
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6eebda9");
  # https://community.teamviewer.com/t5/Change-Logs/Windows-v13-2-5287-Full-Change-Log/m-p/39009#M12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a695b8b0");
  script_set_attribute(attribute:"solution", value:
"Upgrade for Teamviewer 13, upgrade to 13.2.5287 or later. Alternatively, apply the workarounds outlined in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14333");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("teamviewer_detect.nasl");
  script_require_keys("SMB/TeamViewer/Installed", "installed_sw/TeamViewer/");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'TeamViewer');

constraints = [{'min_version': '13.0.0', 'max_version': '13.1.1548', 'fixed_version' : '13.2.5287'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
