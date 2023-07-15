##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147896);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/22");

  script_cve_id("CVE-2019-3465");

  script_name(english:"Tenable SecurityCenter 5.9.x to 5.12.x SimpleSAMLPHP Privilege Escalation (TNS-2020-01)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter application installed on the remote host is 5.9.x,
5.10.x, 5.11.x or 5.12.x. It is, therefore, affected by a privilege escalation vulnerability due to incorrect 
validation of cryptographic signatures in XML messages in the SimpleSAMLPHP third-party component. An authenticated 
attacker can exploit this to impersonate others or elevate privileges by creating a crafted XML message.

Note that Nessus has not tested for these issues nor the stand-alone patch but has instead relied only on the 
application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2020-01-0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.13.0 or later or apply a stand-alone patch to address 
these issues provided by Tenable.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3465");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_keys("Settings/ParanoidReport", "Host/SecurityCenter/Version", "installed_sw/SecurityCenter");

  exit(0);
}

include('vcf_extras.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:443, dont_exit:TRUE);
app_info = vcf::tenable_sc::get_app_info(port:port);

constraints = [
  {'min_version': '5.9.0', 'fixed_version':'5.13.0', 'fixed_display': '5.13.0 or the stand-alone patch obtained from the Tenable Downloads Portal'}
];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
