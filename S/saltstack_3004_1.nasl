#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159497);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2022-22934",
    "CVE-2022-22935",
    "CVE-2022-22936",
    "CVE-2022-22941"
  );
  script_xref(name:"IAVA", value:"2022-A-0128");

  script_name(english:"SaltStack 3000 <  3002.8 / 3003 < 3003.4 / 3004 < 3004.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of SaltStack running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of SaltStack hosted on the remote server is affected by
multiple vulnerabilities:

  - Salt Masters do not sign pillar data with the minion's public key, 
  which can result in attackers substituting arbitrary pillar data. (CVE-2022-22934)

  - Job publishes and file server replies are susceptible to replay attacks, which can 
    result in an attacker replaying job publishes causing minions to run old jobs. (CVE-2022-22936)
  
  - When configured as a Master-of-Masters, with a publisher_acl, if a user configured in the publisher_acl 
    targets any minion connected to the Syndic, the Salt Master incorrectly interpreted no valid targets as 
    valid, allowing configured users to target any of the minions connected to the syndic with their 
    configured commands. (CVE-2022-22941)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version");
  # https://saltproject.io/security_announcements/salt-security-advisory-release/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f399e6f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SaltStack version referenced in the vendor security advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22941");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:saltstack:salt");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("saltstack_salt_linux_installed.nbin");
  script_require_keys("installed_sw/SaltStack Salt Master");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'SaltStack Salt Master');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '3000.0', 'fixed_version' : '3002.8' },
  { 'min_version' : '3003.0', 'fixed_version' : '3003.4' },
  { 'min_version' : '3004.0', 'fixed_version' : '3004.1' }

];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
