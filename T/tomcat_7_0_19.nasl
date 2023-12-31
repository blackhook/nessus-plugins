#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55759);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-2204", "CVE-2011-2481", "CVE-2011-2526");
  script_bugtraq_id(48456, 48667, 49147);

  script_name(english:"Apache Tomcat 7.x < 7.0.17 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.17. It is,
therefore, affected by the following vulnerabilities :

  - An error handling issue exists related to the
    MemoryUserDatabase that allows user passwords to be
    disclosed through log files. (CVE-2011-2204)

  - If loaded before other web applications, a malicious web
    application can potentially access or modify the
    web.xml, context.xml, and TLD files of other web
    applications on the system. (CVE-2011-2481)

  - An input validation error exists that allows a local
    attacker to either bypass security or carry out denial
    of service attacks when the APR or NIO connectors are
    enabled. (CVE-2011-2526)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.19");
  script_set_attribute(attribute:"see_also", value:"https://www.mail-archive.com/announce@tomcat.apache.org/msg00053.html");
  script_set_attribute(attribute:"see_also", value:"https://www.mail-archive.com/announce@tomcat.apache.org/msg00055.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.19 or later. Note that versions
7.0.17 and 7.0.18 are not affected but were never officially released.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"7.0.19", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");

