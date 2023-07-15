#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17727);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2005-2090");
  script_bugtraq_id(13873);

  script_name(english:"Apache Tomcat 5.0.x <= 5.0.30 / 5.5.x < 5.5.23 Content-Length HTTP Request Smuggling");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an HTTP request smuggling
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat listening on the remote host is 5.0.x equal to or prior to
5.0.30 or 5.5.x prior to 5.5.23. It is, therefore, affected by an HTTP
request smuggling vulnerability.

Requests containing multiple 'content-length' headers are not rejected
as invalid. This error can allow web-cache poisoning, cross-site
scripting attacks and information disclosure.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-5.html#Fixed_in_Apache_Tomcat_5.5.23,_5.0.SVN
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb925ad2");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=tomcat-dev&m=120155101522062&w=2");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=tomcat-dev&m=117270879831613&w=2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 5.5.23 or later. Alternatively, use
the latest SVN source for 5.0.x. SVN revision number 513079 fixes the
issue.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-2090");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/01");
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

# nb: 5.0.30 was the last 5.0.x and thus all 5.0.x are vuln
tomcat_check_version(fixed:"5.5.23", min:"5.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^5(\.5)?$");

