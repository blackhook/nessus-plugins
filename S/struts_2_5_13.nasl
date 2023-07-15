#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102960);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-9793",
    "CVE-2017-9804",
    "CVE-2017-9805",
    "CVE-2017-12611"
  );
  script_bugtraq_id(
    100609,
    100611,
    100612,
    100829
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Apache Struts 2.1.x >= 2.1.2 / 2.2.x / 2.3.x < 2.3.34 / 2.5.x < 2.5.13 Multiple Vulnerabilities (S2-050 - S2-053)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.1.x
subsequent or equal to 2.1.2, 2.2.x, 2.3.x prior to 2.3.34, or 2.5.x
prior to 2.5.13. It is, therefore, affected by multiple
vulnerabilities:

  - A remote code execution vulnerability in the REST plugin. The
    Struts REST plugin uses an XStreamHandler with an instance of
    XStream for deserialization and does not perform any type
    filtering when deserializing XML payloads. This can allow an
    unauthenticated, remote attacker to execute arbitrary code in the
    context of the Struts REST plugin by sending a specially crafted
    XML payload. (CVE-2017-9805)

  - A denial of service vulnerability in the XStream XML deserializer
    in the XStreamHandler used by the REST plugin. (CVE-2017-9793)

  - A denial of service vulnerability when using URLValidator.
    (CVE-2017-9804)

  - A flaw exists related to 'freemarker' tags, expression literals,
    'views/freemarker/FreemarkerManager.java', and forced
    expressions that allows arbitrary code execution.
    (CVE-2017-12611)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.3.34");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/Version+Notes+2.5.13");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-050");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-051");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-052");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-053");
  script_set_attribute(attribute:"see_also", value:"https://lgtm.com/blog/apache_struts_CVE-2017-9805_announcement");
  script_set_attribute(attribute:"see_also", value:"https://lgtm.com/blog/apache_struts_CVE-2017-9805");
  # https://www.cisecurity.org/advisory/vulnerability-in-apache-struts-could-allow-for-remote-code-execution-3/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45c4be36");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2017/q3/406");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.34 or 2.5.13 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12611");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Struts REST Plugin XStream RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 REST Plugin XStream RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include("vcf.inc");

app_info = vcf::combined_get_app_info(app:"Apache Struts");

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.1.2", "fixed_version" : "2.3.34" },
  { "min_version" : "2.5.0", "fixed_version" : "2.5.13" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
