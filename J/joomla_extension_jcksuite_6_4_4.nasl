#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121255);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Joomla! Extension 'JCK Suite' - 'jckeditor' =< 6.4.4 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"The remote Joomla! application has a plugin installed that is vulnerable
to a sql injection attack.");
  script_set_attribute(attribute:"description", value:
"The Joomla! application running on the remote host has a version of
'JCK Suite' - 'jckeditor' extension that is prior or equal to 6.4.4.
As such, the host is affected by a SQL injection (SQLi) vulnerability
exists due to improper validation of user-supplied input. An
unauthenticated, remote attacker can exploit this to inject or
manipulate SQL queries in the back-end database, resulting in the
disclosure or manipulation of arbitrary data.");
  script_set_attribute(attribute:"see_also", value:"https://extensions.joomla.org/extension/jck-editor/");
  script_set_attribute(attribute:"see_also", value:"https://www.exploit-db.com/exploits/45423");
  script_set_attribute(attribute:"solution", value:
"Update the 'JCK Suite' - 'jckeditor' extension through the
administrative dashboard.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"standard sql injection");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:joomla:joomla\!");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("joomla_extension_detect.nbin");
  script_require_keys("installed_sw/Joomla!", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::joomla::extension::get_app_info(extension:"jcksuite", subextension:"jckeditor");
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "max_version" : "6.4.4", "fixed_display" : "Consult Vendor" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{'sqli': TRUE});
