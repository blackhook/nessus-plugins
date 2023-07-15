#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(135924);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2020-5346");
  script_bugtraq_id(107210);
  script_xref(name:"IAVB", value:"2020-B-0020");

  script_name(english:"EMC RSA Authentication Manager < 8.4 P11 XSS Vulnerability (DSA-2020-066)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an insecure
credential management vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Authentication Manager running on the remote host is 
prior to 8.4 Patch 11. It is, therefore, affected by stored cross-site scripting
vulnerability in the Security Console. A authorized remote user could exploit this 
vulnerability to store arbitrary HTML or JavaScript code through the Security Console 
web interface. When other Security Console administrators open the affected page, 
the injected scripts could potentially be executed in their browser.");
  script_set_attribute(attribute:"see_also", value:"https://nvd.nist.gov/vuln/detail/CVE-2020-5346");
  # https://www.dell.com/support/security/en-us/details/DOC-111347/DSA-2020-066-RSA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ede1199");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Authentication Manager version 8.4 Patch 11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5346");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/23");

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
  { 'fixed_version' : '8.4.0.11', 'fixed_display' : '8.4 Patch 11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
