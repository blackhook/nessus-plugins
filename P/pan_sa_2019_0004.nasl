#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135238);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/09");

  script_cve_id("CVE-2019-1569", "CVE-2019-1570", "CVE-2019-1571");

  script_name(english:"Palo Alto Expedition Cross-Site Scripting");

  script_set_attribute(attribute:"synopsis", value:
"The reported version of Palo Alto Expedition is vulnerable to Cross-Site Scripting.");
  script_set_attribute(attribute:"description", value:
"Multiple cross-site scripting (XSS) vulnerability exists in Palo ALto Expedition Migration Tool in versions less than or
equal to 1.1.8 due to improper validation of user-supplied input before returning it to users.

  - An authenticated remote attacker may be able to inject arbitrary JavaScript or HTML in the User Mapping settings (CVE-2019-1569).

  - An authenticated remote attacker may be able to inject arbitrary JavaScript or HTML in the LDAP server settings (CVE-2019-1570).

  - An authenticated remote attacker may be able to inject arbitrary JavaScript or HTML in the Radius server settings (CVE-2019-1571).");
  script_set_attribute(attribute:"see_also", value:"https://security.paloaltonetworks.com/PAN-SA-2019-0004");
  script_set_attribute(attribute:"solution", value:
"Update to Palo Alto Expedition version 1.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1569");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:paloaltonetworks:expedition_migration_tool");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_expedition_web_detect.nbin");
  script_require_keys("installed_sw/Palo Alto Expedition");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:443, embedded:TRUE);
app_info = vcf::get_app_info(app:'Palo Alto Expedition', port:port);

if (!app_info['version']) audit(AUDIT_UNKNOWN_APP_VER, "Palo Alto Expedition");

constraints = [
{ 'min_version' : '0.0', 'fixed_version' : '1.1.8' }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE,
  flags: {xss:true}
);
