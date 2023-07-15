#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135179);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2020-5339");
  script_bugtraq_id(107210);
  script_xref(name:"IAVB", value:"2020-B-0017-S");

  script_name(english:"EMC RSA Authentication Manager < 8.4 P10 Multiple Vulnerabilites (DSA-2020-052)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an insecure
credential management vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Authentication Manager running on the remote host is 
prior to 8.4 Patch 10. It is, therefore, affected by multiple vulnerabilities:

  - A cross-site scripting (XSS) vulnerability exists in 
    Security Console due to improper validation of 
    user-supplied input before returning it to users. 
    An authenticated, remote attacker can exploit this 
    to store code in a Security Console report that will 
    then be run by other Security Console administrators 
    accessing a report page. (CVE-2020-5339)

  - A cross-site scripting (XSS) vulnerability exists in 
    Security Console due to improper validation of 
    user-supplied input before returning it to users. 
    An authenticated, remote attacker can exploit this 
    to store code in a Security Console default security 
    domain mapping that will then be run by other Security 
    Console administrators attempting to change the default 
    security domain mapping. (CVE-2020-5340)");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2020-5339");
  # https://www.dell.com/support/security/en-ie/details/DOC-111092/DSA-2020-052-RSA&
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1e30067");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Authentication Manager version 8.4 Patch 10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5339");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_am_detect.nbin");
  script_require_keys("installed_sw/EMC RSA Authentication Manager");
  script_require_ports("Services/www", 7004);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:7004);
app ='EMC RSA Authentication Manager';
app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { 'fixed_version' : '8.4.0.10', 'fixed_display' : '8.4 Patch 10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
