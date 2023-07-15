##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(106978);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2018-1304", "CVE-2018-1305");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.5 Insecure CGI Servlet Search Algorithm Description Weakness");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 9.0.x prior to 9.0.5. It is, therefore, affected by a
security constraints flaw which could expose resources to unauthorized users.);   #
http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.5   script_set_attribute(attribute:see_also,
value:http://www.nessus.org/u?909ff130

  - The URL pattern of  (the empty string) which exactly maps to the context root was not correctly handled
    in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to 8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 when used as
    part of a security constraint definition. This caused the constraint to be ignored. It was, therefore,
    possible for unauthorised users to gain access to web application resources that should have been
    protected. Only security constraints with a URL pattern of the empty string were affected. (CVE-2018-1304)

  - Security constraints defined by annotations of Servlets in Apache Tomcat 9.0.0.M1 to 9.0.4, 8.5.0 to
    8.5.27, 8.0.0.RC1 to 8.0.49 and 7.0.0 to 7.0.84 were only applied once a Servlet had been loaded. Because
    security constraints defined in this way apply to the URL pattern and any URLs below that point, it was
    possible - depending on the order Servlets were loaded - for some security constraints not to be applied.
    This could have exposed resources to users who were not authorised to access them. (CVE-2018-1305)");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1823310");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1824323");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1823306");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=62067");
  script_set_attribute(attribute:"see_also", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.5 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1304");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '9.0.5', min:'9.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^9(\.0)?$");
