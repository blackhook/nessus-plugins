#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121064);
  script_version("1.4");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2018-15780");
  script_bugtraq_id(106396);

  script_name(english:"EMC RSA Archer 6.x < 6.4.10500.1006 Authorization Bypass Vulnerability");
  script_summary(english:"Checks for the product and version in the login page.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote host is affected by an
authorization bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of EMC RSA Archer running on the remote web server is 6.x
prior to 6.4.10500.1006 (6.4 SP1 patch 5). It is, therefore, affected by
an authorization bypass vulnerability. An authenticated attacker could
leverage this vulnerability to gain read access to restricted user
information.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2019/Jan/3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC RSA Archer version 6.4.10500.1006 (6.4 SP1 patch 5) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15780");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:rsa_archer_egrc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("emc_rsa_archer_detect.nbin");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

app_name = "EMC RSA Archer";
port = get_http_port(default:80);

app_info = vcf::get_app_info(app:app_name, webapp:TRUE, port:port);

constraints = [
  {"fixed_version" : "6.4.10500.1006", "fixed_display" : "6.4 SP1 patch 5 (6.4.10500.1006)" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
