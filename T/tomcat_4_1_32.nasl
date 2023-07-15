#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47029);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2005-3510",
    "CVE-2005-4838",
    "CVE-2006-3835",
    "CVE-2006-7196",
    "CVE-2007-1858",
    "CVE-2008-3271"
  );
  script_bugtraq_id(
    15325,
    19106,
    25531,
    28482,
    31698
  );
  script_xref(name:"SECUNIA", value:"13737");
  script_xref(name:"SECUNIA", value:"17416");
  script_xref(name:"SECUNIA", value:"32213");

  script_name(english:"Apache Tomcat 4.x < 4.1.32 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 4.x listening on the remote host is prior to 4.1.32. It is,
therefore, affected by the following vulnerabilities :

  - The remote Apache Tomcat install is vulnerable to a
    denial of service attack. If directory listing is
    enabled, function calls to retrieve the contents of
    large directories can degrade performance.
    (CVE-2005-3510)

  - The remote Apache Tomcat install may be vulnerable to
    a cross-site scripting attack if the JSP examples are
    enabled. Several of these JSP examples do not properly
    validate user input. (CVE-2005-4838)

  - The remote Apache Tomcat install allows remote users
    to list the contents of a directory by placing a
    semicolon before a filename with a mapped extension.
    (CVE-2006-3835)

  - If enabled, the JSP calendar example application is
    vulnerable to a cross-site scripting attack because
    user input is not properly validated. (CVE-2006-7196)

  - The remote Apache Tomcat install, in its default
    configuration, permits the use of insecure ciphers when
    using SSL. (CVE-2007-1858)

  - The remote Apache Tomcat install may be vulnerable to an
    information disclosure attack by allowing requests from
    a non-permitted IP address to gain access to a context
    that is protected with a valve that extends
    RequestFilterValve. (CVE-2008-3271)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.32");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=25835");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 4.1.32 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-3510");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/16");

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

tomcat_check_version(fixed:"4.1.32", min:"4.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^4(\.1)?$");

