#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90153);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-0785",
    "CVE-2016-2162",
    "CVE-2016-3093",
    "CVE-2016-4003"
  );
  script_bugtraq_id(
    85066,
    85070,
    86311,
    90961
  );

  script_name(english:"Apache Struts 2.x < 2.3.28 Multiple Vulnerabilities (S2-028) (S2-029) (S2-030) (S2-034)");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework
that is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.x
prior to 2.3.28. It is, therefore, affected by the following
vulnerabilities :
  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input when using
    a single byte page encoding. A remote attacker can 
    exploit this, via non-spec URL-encoded parameter value
    including multi-byte characters. (CVE-2016-4003)

  - A remote code execution vulnerability exists due to
    double OGNL evaluation of attribute values assigned to
    certain tags. An unauthenticated, remote attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary code. (CVE-2016-0785)

  - A cross-site scripting vulnerability exists due to
    improper validation of user-supplied input when using
    the I18NInterceptor. A remote attacker can exploit this,
    via a specially crafted request, to execute arbitrary
    script code in a user's browser session. (CVE-2016-2162)

  - A denial of service vulnerability exists in the
    Object-Graph Navigation Language (OGNL) component due to
    a flaw in the implementation of the cache for stored
    method references. A context-dependent attacker can
    exploit this to block access to arbitrary websites.
    (CVE-2016-3093)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-028.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-029.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-030.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-034.html");
  script_set_attribute(attribute:"see_also", value:"http://struts.apache.org/docs/version-notes-2328.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.28 or later. Alternatively,
apply the workaround referenced in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0785");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin", "struts_config_browser_detect.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include("vcf.inc");

app_info = vcf::combined_get_app_info(app:"Apache Struts");

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.0.0", "max_version" : "2.3.24.1", "fixed_version" : "2.3.28" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
