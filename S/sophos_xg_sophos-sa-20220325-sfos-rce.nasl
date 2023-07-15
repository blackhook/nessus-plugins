#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159541);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2022-1040");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/21");

  script_name(english:"Sophos XG Firewall <= 18.5.3 RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Sophos XG Firewall is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in
Sophos Firewall version v18.5 MR3 and older.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.sophos.com/en-us/security-advisories/sophos-sa-20220325-sfos-rce
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddc1a2cb");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1040");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/06");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sophos:xg_firewall_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sophos_xg_firewall_detect.nbin");
  script_require_keys("installed_sw/Sophos XG Firewall", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app_name = 'Sophos XG Firewall';
var port = get_http_port(default:443);
var app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

# Not checking hotfixes
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'0.0', 'max_version':'18.5.3', 'fixed_display':'See vendor advisory'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
