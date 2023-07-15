#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106979);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-1287");
  script_bugtraq_id(103068);

  script_name(english:"Apache JMeter < 4.0 Insecure RMI Registry Binding");

  script_set_attribute(attribute:"synopsis", value:
"A java application on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"One or more versions of Apache JMeter discovered on the remote
host is affected by a remote code execution vulnerability as a result
of insecure RMI registry binding.");
  # http://mail-archives.apache.org/mod_mbox/www-announce/201802.mbox/%3CCAH9fUpYsFx1%2Brwz1A%3Dmc7wAgbDHARyj1VrWNg41y9OySuL1mqw%40mail.gmail.com%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99974636");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache JMeter 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1287");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:jmeter");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_jmeter_detect_win.nbin");
  script_require_keys("installed_sw/Apache JMeter");

  exit(0);
}

include("vcf.inc");

app = "Apache JMeter";
get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app);

constraints = [
  { "min_version" : "2.0", "fixed_version" : "4.0" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
