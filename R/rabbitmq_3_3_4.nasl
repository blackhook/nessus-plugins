#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144631);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-9494");
  script_bugtraq_id(71859);

  script_name(english:"Pivotal RabbitMQ < 3.3.4 Security Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote web server is affected by
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pivotal
RabbitMQ running on the remote web server is prior to 3.3.4. It is, 
therefore, affected by security bypass vulnerability. An unauthenticated,
remote attacker could bypass security restrictions, caused by the improper 
handling of malicious headers when determining the remote address. By 
sending a specially-crafted X-Forwarded-For header, an attacker could 
exploit this vulnerability to connect to the broker as if they were a 
localhost user.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/99685");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2015/q1/30");
  script_set_attribute(attribute:"see_also", value:"https://www.rabbitmq.com/release-notes/README-3.4.0.txt");
  script_set_attribute(attribute:"see_also", value:"https://groups.google.com/g/rabbitmq-users/c/DMkypbSvIyM");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pivotal RabbitMQ version 3.3.4 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9494");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:rabbitmq");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rabbitmq_server_nix_installed.nbin");
  script_require_keys("installed_sw/RabbitMQ");

  exit(0);
}

include('vcf.inc');


app_info = vcf::get_app_info(app:'RabbitMQ', port:port);

if (app_info['Managed']) audit(AUDIT_HOST_NOT, 'relevant to this plugin as RabbitMQ was installed by a package manager');

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [{'fixed_version' : '3.3.4' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
