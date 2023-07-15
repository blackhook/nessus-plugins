#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(52634);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-1088", "CVE-2011-1419");
  script_bugtraq_id(46685);
  script_xref(name:"SECUNIA", value:"43684");

  script_name(english:"Apache Tomcat 7.x < 7.0.11 @ServletSecurity Annotation Security Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.11, It is,
therefore affected by a security bypass vulnerability.

When a web application is started, 'ServletSecurity' annotations might
be ignored which could lead to some areas of the applications not
being protected as expected.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.11_(released_11_Mar_2011)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e95c3250");
  # http://mail-archives.apache.org/mod_mbox/www-announce/201103.mbox/%3C4D6E74FF.7050106@apache.org%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfd5efff");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.11 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/11");

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

tomcat_check_version(fixed:"7.0.11", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");

