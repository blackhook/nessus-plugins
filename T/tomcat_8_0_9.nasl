#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81580);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-0227", "CVE-2014-0230");
  script_bugtraq_id(72717, 74475);

  script_name(english:"Apache Tomcat 8.0.x < 8.0.9 Multiple DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple denial of
service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
server running on the remote host is 8.0.x prior to version 8.0.9. It
is, therefore, affected by the following vulnerabilities :

  - A flaw in 'ChunkedInputFilter.java' due to improper
    handling of attempts to continue reading data after an
    error has occurred. A remote attacker, using streaming
    data with malformed chunked transfer coding, can
    exploit this to conduct HTTP request smuggling or cause
    a denial of service. (CVE-2014-0227)

  - An error exists due to a failure to limit the size of
    discarded requests. A remote attacker can exploit this
    to exhaust available memory resources, resulting in a
    denial of service condition. (CVE-2014-0230)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2015/Feb/65");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/tomcat-8.0-doc/changelog.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 8.0.9 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0227");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"8.0.9", min:"8.0.0", severity:SECURITY_WARNING, granularity_regex:"^8(\.0)?$");

