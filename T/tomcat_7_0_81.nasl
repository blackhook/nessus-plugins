#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103329);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2017-12615", "CVE-2017-12616");
  script_bugtraq_id(100897, 100901);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"Apache Tomcat 7.0.x < 7.0.81 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 7.0.x
prior to 7.0.81. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified vulnerability when running on Windows
    with HTTP PUTs enabled (e.g. via setting the readonly
    initialization parameter of the Default to false) makes
    it possible to upload a JSP file to the server via a
    specially crafted request. This JSP could then be
    requested and any code it contained would be
    executed by the server. (CVE-2017-12615, CVE-2017-12617)

  - When using a VirtualDirContext it was possible to bypass
    security constraints and/or view the source code of JSPs
    for resources served by the VirtualDirContext using a
    specially crafted request. (CVE-2017-12616)

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.81
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6b65377");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.81 or later.

Note that the remote code execution issue was fixed in Apache Tomcat
7.0.80 but the release vote for the 7.0.81 release candidate did not
pass. Therefore, although users must download 7.0.81 to obtain a
version that includes the fix for this issue, version 7.0.80 is not
included in the list of affected versions.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-12615");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Tomcat VirtualDirContext Class File Handling Remote JSP Source Code Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/19");

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

tomcat_check_version(fixed:"7.0.80", fixed_display:"7.0.81", min:"7.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");

