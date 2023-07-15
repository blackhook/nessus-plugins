#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132313);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-14838");
  script_xref(name:"RHSA", value:"2019:3083");

  script_name(english:"Red Hat JBoss Enterprise Application Platform 7.x < 7.2.4 Authorization Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat JBoss Enterprise Application Platform installation is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Red Hat JBoss Enterprise Application Platform (EAP) installed
on the remote host is 7.x prior to 7.2.4. It is therefore, affected my multiple
vulnerabilities as referenced in the RHSA-2019: advisory:

  - wildfly-core: Incorrect privileges for 'Monitor', 'Auditor' and 'Deployer'
  user by default (CVE-2019-14838)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2019:3083");
  script_set_attribute(attribute:"solution", value:
"Update to Red Hat JBoss Enterprise Application Platform 7.2.4 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14838");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:redhat:jboss_enterprise_application_platform");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jboss_detect.nbin");
  script_require_keys("installed_sw/JBoss");

  exit(0);
}

include('lists.inc');
include('vcf.inc');
include('vcf_extras.inc');

vcf::jboss::eap::initialize();
app_info = vcf::jboss::eap::get_app_info();

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '7', 'fixed_version' : '7.2.4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
