#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136402);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-11651", "CVE-2020-11652");
  script_xref(name:"IAVA", value:"2020-A-0195-S");
  script_xref(name:"EDB-ID", value:"48421");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0041");

  script_name(english:"SaltStack < 2019.2.4 / 3000.x < 3000.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of SaltStack running on the remote server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of SaltStack hosted on the remote server is prior to
2019.2.4, 3000.x prior to 3000.2. It is, therefore, affected by multiple vulnerabilities:

  - An authentication bypass vulnerabilities exists in the ClearFuncs class due to improper validation of
    method calls. An unauthenticated, remote attacker can exploit this by accessing exposed methods to trigger
    minions to run arbitrary commands as root, or to retrieve the root key to authenticate commands from the
    local root user on the master server. (CVE-2020-11651)

  - A directory traversal vulnerabilities exists in the ClearFuncs class due to improper path sanitization. An
    authenticated, remote attacker can exploit this by accessing the exposed get_token() method which allows
    the insertion of double periods in the filename parameter to read files outside of the intended directory.
    The only restriction is that the file has to be deserializable by salt.payload.Serial.loads().
    (CVE-2020-11652)");
  # https://labs.f-secure.com/advisories/saltstack-authorization-bypass
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4df67f57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SaltStack version 2019.2.4, 3000.2 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11651");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt Master/Minion Unauthenticated RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:saltstack:salt");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("saltstack_salt_linux_installed.nbin");
  script_require_keys("installed_sw/SaltStack Salt Master");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'SaltStack Salt Master');

vcf::check_all_backporting(app_info:app_info);

constraints = [
  { 'fixed_version' : '2019.2.0', 'fixed_display' : '2019.2.4, 3000.2 or later.' },
  { 'min_version' : '2019.2.0', 'fixed_version' : '2019.2.4' },
  { 'min_version' : '3000.0', 'fixed_version' : '3000.2' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
