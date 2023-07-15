#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144629);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-11281");

  script_name(english:"Pivotal RabbitMQ < 3.7.18 Cross Site Scripting (XSS) Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote web server is affected by
cross site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pivotal
RabbitMQ running on the remote web server is prior to 3.7.18. It is, 
therefore, affected by cross site scripting (XSS) vulnerability.
A cross-site scripting (XSS) vulnerability exists in two components, 
the virtual host limits page, and the federation management UI 
due to unsanitize user input. An authenticated, remote attacker can 
exploit this, by crafting a cross site scripting attack that would 
gain access to virtual hosts and policy management information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://pivotal.io/security/cve-2019-11281");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:0078");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pivotal RabbitMQ version 3.7.18 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11281");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/16");
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

constraints = [{'fixed_version' : '3.7.18'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
