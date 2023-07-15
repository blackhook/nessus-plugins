#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17726);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-2090", "CVE-2007-0450", "CVE-2007-1358");
  script_bugtraq_id(13873, 22960, 24524);

  script_name(english:"Apache Tomcat 4.x < 4.1.36 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 4.x listening on the remote host is prior to 4.1.36. It is,
therefore, affected by the following vulnerabilities :

  - Requests containing multiple 'content-length' headers
    are not rejected as invalid. This error can allow
    web-cache poisoning, cross-site scripting attacks and
    information disclosure. (CVE-2005-2090)

  - An input sanitization error exists that can allow
    disclosure of sensitive information via directory
    traversal. This vulnerability is exposed when the
    server is configured to use the 'Proxy' module.
    (CVE-2007-0450)

  - 'Accept-Language' headers are not validated properly,
    which can allow cross-site scripting attacks.
    (CVE-2007-1358)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.36");
  script_set_attribute(attribute:"solution", value:
"Update to Apache Tomcat version 4.1.36 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2090");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/18");

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

tomcat_check_version(fixed:"4.1.36", min:"4.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^4(\.1)?$");

