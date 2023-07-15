#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50475);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2002-2006", "CVE-2003-0866");
  script_bugtraq_id(4575, 5542, 8824);

  script_name(english:"Apache Tomcat 4.x < 4.1.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 4.x listening on the remote host is prior to 4.1.0. It is,
therefore, affected by multiple vulnerabilities :

  - An error exists in the handling of malformed packets
    that can cause the processing thread to become
    unresponsive. A sequence of such requests can cause all
    threads to become unresponsive. (CVE-2003-0866)

  - Two example servlets, 'snoop' and a troubleshooting
    servlet, disclose the Apache Tomcat installation path.
    (CVE-2002-2006)

  - It has also been reported that this version of Tomcat
    is affected by a cross-site scripting vulnerability.
    The contents of a request URL are not sanitized before
    being returned to the browser should an error occur.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.0");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2002/Apr/322");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 4.1.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2003-0866");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/04");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include("tomcat_version.inc");

tomcat_check_version(fixed:"4.1.0", min:"4.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^4$");

