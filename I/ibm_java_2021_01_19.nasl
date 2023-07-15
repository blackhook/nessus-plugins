#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160363);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-14803");
  script_xref(name:"IAVA", value:"2020-A-0477-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"IBM Java 7.0 < 7.0.10.80 / 7.1 < 7.1.4.80 / 8.0 < 8.0.6.25");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 7.0 < 7.0.10.80 / 7.1 < 7.1.4.80 / 8.0 < 8.0.6.25. It
is, therefore, affected by a vulnerability as referenced in the Oracle January 19 2021 CPU advisory.

  - Vulnerability in the Java SE product of Oracle Java SE (component: Libraries). Supported versions that are
    affected are Java SE: 11.0.8 and 15. Easily exploitable vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in
    servers, that load and run only trusted code (e.g., code installed by an administrator). (CVE-2020-14803)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ30419");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_January_19_2021_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c55b76d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle January 19 2021 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14803");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_java_nix_installed.nbin", "ibm_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['IBM Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.80' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.80' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.6.25' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
