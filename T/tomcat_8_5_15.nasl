#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100681);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-5664");
  script_bugtraq_id(98888);

  script_name(english:"Apache Tomcat 7.0.x < 7.0.78 / 8.0.x < 8.0.44 / 8.5.x < 8.5.15 / 9.0.x < 9.0.0.M21 Remote Error Page Manipulation");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a remote error page
manipulation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
service running on the remote host is 7.0.x prior to 7.0.78, 8.0.x
prior to 8.0.44, 8.5.x prior to 8.5.15, or 9.0.x prior to 9.0.0.M21.
It is, therefore, affected by an implementation flaw in the error 
page reporting mechanism in which it does not conform to the Java 
Servlet Specification that requires static error pages to be processed 
as an HTTP GET request nothwithstanding the HTTP request method that 
was originally used when the error occurred. Depending on the original 
request and the configuration of the Default Servlet, an 
unauthenticated, remote attacker can exploit this issue to replace or 
remove custom error pages.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.78");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.44");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.15");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M21
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a774a43b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.78 / 8.0.44 / 8.5.15 / 9.0.0.M21 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5664");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed:make_list("7.0.78", "8.0.44", "8.5.15", "9.0.0.M21"), severity:SECURITY_WARNING, granularity_regex:"^(7(\.0)?|8(\.(0|5))?|9(\.0)?)$");
