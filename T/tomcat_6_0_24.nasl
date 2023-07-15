#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104358);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2017-5647",
    "CVE-2017-5664",
    "CVE-2017-12615",
    "CVE-2017-12617"
  );
  script_bugtraq_id(98888, 100901, 100954);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"Apache Tomcat 6.0.x < 6.0.24 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 6.0.x
prior to 6.0.24. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the handling of pipelined requests
    when 'Sendfile' was used. If sendfile processing completed
    quickly, it was possible for the Processor to be added to the
    processor cache twice. This could lead to invalid responses or
    information disclosure. (CVE-2017-5647)

  - An unspecified flaw in error page mechanism of the DefaultServlet
    implementation allows a specially-crafted HTTP request to cause
    undesired side effects, including the removal or replacement of
    the custom error page. (CVE-2017-5664)

  - An unspecified flaw affects servlet contexts configured as
    readonly=false with HTTP PUT requests allowed. An attacker can
    upload a JSP file to that context and execute arbitrary code.
    (CVE-2017-12615, CVE-2017-12617)

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 6.0.24 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12617");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat for Windows HTTP PUT Method File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Tomcat RCE via JSP Upload Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"6.0.24", min:"6.0", severity:SECURITY_WARNING, granularity_regex:"^6(\.0)?$");

