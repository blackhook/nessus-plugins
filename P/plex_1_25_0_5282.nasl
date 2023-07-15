#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156380);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/30");

  script_cve_id("CVE-2021-42835");

  script_name(english:"Plex Media Server < 1.25.0.5282 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"A client-server media player running on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Plex Media Server installed on the remote Windows host is
prior to 1.25.0.5282. It is, therefore, affected by a privilege escalation vulnerability. A local, authenticated user
can exploit this to gain elevated privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://forums.plex.tv/t/security-regarding-cve-2021-42835/761510");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Plex Media Server version 1.25.0.5282 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42835");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:plex:plex_media_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'fixed_version' : '1.25.0.5282' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

