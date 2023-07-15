#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137326);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/10");

  script_cve_id("CVE-2020-5741");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/31");

  script_name(english:"Plex Media Server < 1.19.3 Authenticated RCE");

  script_set_attribute(attribute:"synopsis", value:
"A client-server media player running on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Plex Media Server installed on the remote Windows host is
prior to 1.19.3. It is, therefore, affected by an authenticated remote code execution vulnerability in the camera upload
feature. An authenticated, remote attacker can exploit this, by uploading a malicious file via the camera upload
feature, to cause arbitrary python code to be executed in the context of the current OS user..

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2020-32");
  script_set_attribute(attribute:"see_also", value:"https://forums.plex.tv/t/security-regarding-cve-2020-5741/586819");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Plex Media Server version 1.19.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5741");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Plex Unpickle Dict Windows RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plex:plex_media_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("plex_detect.nbin", "os_fingerprint.nasl", "plex_win_installed.nbin");
  script_require_keys("installed_sw/Plex Media Server", "Host/OS");

  exit(0);
}

include('http.inc');
include('vcf.inc');

# This vulnerability only affects Windows hosts
os = get_kb_item_or_exit('Host/OS');
if ('windows' >!< tolower(os))
  audit(AUDIT_OS_NOT, 'Windows');

app_info = vcf::combined_get_app_info(app:'Plex Media Server');

constraints = [
  { 'fixed_version' : '1.19.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

