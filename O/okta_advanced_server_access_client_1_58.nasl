#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177211);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/14");

  script_cve_id("CVE-2022-1030");

  script_name(english:"Okta Advanced Server Access Client < 1.58.0 Command Injection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by by a command injection vulnerability");
  script_set_attribute(attribute:"description", value:
"The versions of Okta Advanced Server Access Client installed on the remote host is affected by a command injection
vulnerability via a specially crafted URL. An attacker, who has knowledge of a valid team name for the victim and also
knows a valid target host where the user has access, can execute commands on the local system.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://trust.okta.com/security-advisories/okta-advanced-server-access-client-cve-2022-1030/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05fda349");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.58.0 or later");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1030");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:okta:advanced_server_access");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("okta_advanced_server_access_client_mac_installed.nbin", "okta_advanced_server_access_client_nix_installed.nbin");
  script_require_keys("installed_sw/Okta Advanced Server Access Client");
  script_exclude_keys("SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
{
  audit(AUDIT_HOST_NOT, 'affected');
}

var app_info = vcf::get_app_info(app:'Okta Advanced Server Access Client', win_local:FALSE);

var constraints = [
  {'fixed_version' : '1.58.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
