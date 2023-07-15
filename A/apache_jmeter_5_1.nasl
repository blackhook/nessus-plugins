#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122718);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-0187");
  script_bugtraq_id(107219);
  script_xref(name:"IAVB", value:"2019-B-0015");

  script_name(english:"Apache JMeter < 5.1 Unauthenticated Remote Code Execution Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"A java application on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"One or more versions of Apache JMeter discovered on the remote
host is affected by an unauthenticated remote code execution 
vulnerability which is possible when JMeter is used in distributed
mode.");
  # https://mail-archives.apache.org/mod_mbox/jmeter-user/201903.mbox/%3CCAH9fUpaUQaFbgY1Zh4OvKSL4wdvGAmVt+n4fegibDoAxK5XARw@mail.gmail.com%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1eee1eb6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache JMeter 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:jmeter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_jmeter_detect_win.nbin");
  script_require_keys("installed_sw/Apache JMeter");

  exit(0);
}

include("vcf.inc");

app = "Apache JMeter";
get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app);

constraints = [
  { "min_version" : "4.0", "fixed_version" : "5.1" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
