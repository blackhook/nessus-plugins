#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100843);
  script_version("1.4");
  script_cvs_date("Date: 2018/09/06 16:14:34");

  script_cve_id("CVE-2017-6639", "CVE-2017-6640");
  script_bugtraq_id(98935, 98937);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd09961");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvd95346");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170607-dcnm1");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170607-dcnm2");

  script_name(english:"Cisco Prime Data Center Network Manager 10.1.x < 10.2.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the DCNM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Prime Data
Center Network Manager (DCNM) installed on the remote host is 10.1.x
prior to 10.2.1. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists in the
    role-based access control (RBAC) functionality due to a
    lack of authentication and authorization mechanisms for
    a debugging tool. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code with root
    privileges. (CVE-2017-6639)

  - A flaw exists due to the presence of a default user
    account with a static password that is not automatically
    removed post-installation. An unauthenticated, remote
    attacker can exploit this to login and gain root or
    system-level privileges. (CVE-2017-6640)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-dcnm1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f182f37");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd09961");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-dcnm2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5542fca3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvd95346");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco Prime Data Center Network Manager version 10.2.1 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl");
  script_require_ports("installed_sw/Cisco Prime DCNM");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("vcf.inc");

app = 'Cisco Prime DCNM';

get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
      {"min_version" : "10.1.1.0", "max_version" : "10.1.2.0", "fixed_version" : "10.2(1)"  }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
