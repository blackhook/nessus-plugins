#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132319);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2019-14864",
    "CVE-2019-19340",
    "CVE-2019-19341",
    "CVE-2019-19342"
  );

  script_name(english:"Ansible Tower 3.5.x < 3.5.4 / 3.6.x < 3.6.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An IT monitoring application running on the remote host is affected by an Information Disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Ansible Tower running on the remote web server is 3.5.x prior to 3.5.4 or 3.6.x prior to 3.6.2. It is,
therefore, affected by multiple vulnerabilities.

  - An information disclosure vulnerability exists in the Sumologic and Splunk callback plugins due to Ansible
    not respecting the 'no_log' flag. A remote attacker can exploit this via the plugin collectors to
    potentially disclose sensitive information.  (CVE-2019-14864)

  - A flaw exists in RabbitMQ manager with the rabbitmq_enable_manager setting due to the setting exposing the
    RabbigMQ manager management interface publicly, which may still have the default admin user active. An
    unauthenticated, remote attacker can exploit this by guessing the default admin credentials and gain
    access to the system. (CVE-2019-19340)

  - An information disclosure vulnerability exists in Ansible Tower backups, due to files in
    '/var/backup/tower' being left world-readable while a Tower backup is running. An authenticated, remote
    attacker with knowledge of the backup can exploit this by navigating to the '/var/backup/tower' directory
    and accessing the files, which includes both the SECRET_KEY, backup files, and every credential stored in
    Tower. (CVE-2019-19341)

  - An information disclosure vulnerability exists in '/websocket' due to Ansible Tower mishandling passwords
    with the '#' character, and partially disclosing plaintext passwords when '/websocket' is requested. An
    unauthenticated, remote attacker can exploit this via HTTP to disclose partial passwords, allowing the
    attacker to brute force or guess predictable passwords. (CVE-2019-19342)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:4242");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:4243");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-14864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-19340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-19341");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2019-19342");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ansible Tower version 3.5.4, 3.6.2, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19340");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ansible:tower");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ansible_tower_installed.nbin", "ansible_tower_detect.nbin");
  script_require_ports("installed_sw/Ansible Tower", "installed_sw/Ansible Tower WebUI", 80, 443);

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('vcf.inc');

if(!isnull(get_kb_item('installed_sw/Ansible Tower')))
  app = vcf::get_app_info(app:'Ansible Tower');
else
{
  port = get_http_port(default:443);
  app = vcf::get_app_info(app:'Ansible Tower WebUI', webapp:TRUE, port:port);
}

constraints =
[
  {'min_version' : '3.5.0', 'fixed_version' : '3.5.4'},
  {'min_version' : '3.6.0', 'fixed_version' : '3.6.2'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
