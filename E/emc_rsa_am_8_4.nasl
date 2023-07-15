#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121232);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-15782");
  script_bugtraq_id(106633);

  script_name(english:"EMC RSA Authentication Manager < 8.4 Relative Path Traversal (DSA-2018-226)");
  script_summary(english:"Checks the version of EMC RSA Authentication Manager.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by a path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Authentication Manager running on the remote
host is prior to 8.4. It is, therefore, affected by a relative path
traversal vulnerability in the Quick Setup component. An attacker
could provide an administrator with a maliciously crafted license file
to be used during the initial quick setup of RSA Authentication 
Manager, granting unauthorized access to the system.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2019/Jan/18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Authentication Manager version 8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_authentication_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_am_detect.nbin");
  script_require_keys("installed_sw/EMC RSA Authentication Manager");
  script_require_ports("Services/www", 7004);

  exit(0);
}

include("http.inc");
include("vcf.inc");

port = get_http_port(default:7004);

app_info = vcf::get_app_info(app:"EMC RSA Authentication Manager", port:port, webapp:TRUE);

constraints = [{ "fixed_version" : "8.4" }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
