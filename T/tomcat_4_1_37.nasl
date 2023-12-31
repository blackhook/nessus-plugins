#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47030);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2005-3164",
    "CVE-2007-1355",
    "CVE-2007-2449",
    "CVE-2007-2450",
    "CVE-2007-3382",
    "CVE-2007-3383",
    "CVE-2007-3385",
    "CVE-2007-5333",
    "CVE-2007-5461"
  );
  script_bugtraq_id(
    15003,
    24058,
    24475,
    24476,
    24999,
    25316,
    26070,
    27706
  );
  script_xref(name:"SECUNIA", value:"27398");
  script_xref(name:"SECUNIA", value:"28878");
  script_xref(name:"SECUNIA", value:"25678");
  script_xref(name:"SECUNIA", value:"26466");

  script_name(english:"Apache Tomcat 4.x < 4.1.37 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 4.x listening on the remote host is prior to 4.1.37. It is,
therefore, affected by the following vulnerabilities :

  - The remote Apache Tomcat install may be vulnerable to an
    information disclosure attack if the deprecated AJP
    connector processes a client request having a non-zero
    Content-Length and the client disconnects before
    sending the request body. (CVE-2005-3164)

  - The remote Apache Tomcat install may be vulnerable to
    a cross-site scripting attack if the JSP and Servlet
    examples are enabled. Several of these examples do
    not properly validate user input.
    (CVE-2007-1355, CVE-2007-2449)

  - The remote Apache Tomcat install may be vulnerable to
    a cross-site scripting attack if the Manager web
    application is enabled as it fails to escape input
    data. (CVE-2007-2450)

  - The remote Apache Tomcat install may be vulnerable to an
    information disclosure attack via cookies. Apache Tomcat
    treats the single quote character in a cookie as a
    delimiter which can lead to information, such as session
    ID, to be disclosed. (CVE-2007-3382)

  - The remote Apache Tomcat install may be vulnerable to
    a cross-site scripting attack if the SendMailServlet is
    enabled. The SendMailServlet is a part of the examples
    web application and, when reporting error messages,
    fails to escape user provided data. (CVE-2007-3383)

  - The remote Apache Tomcat install may be vulnerable to an
    information disclosure attack via cookies. The previous
    fix for CVE-2007-3385 was incomplete and did not account
    for the use of quotes or '%5C' in cookie values.
    (CVE-2007-3385, CVE-2007-5333)

  - The remote Apache Tomcat install may be vulnerable to an
    information disclosure attack via the WebDAV servlet.
    Certain WebDAV requests, containing an entity with a
    SYSTEM tag, can result in the disclosure of arbitrary
    file contents. (CVE-2007-5461)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number..");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_4.1.37");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/469067/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/471351/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/471357/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/476442/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/474413/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/476444/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/487822/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.securityfocus.com/archive/1/archive/1/507985/100/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 4.1.37 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2005-3164");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 79, 200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/09");
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

tomcat_check_version(fixed:"4.1.37", min:"4.0.0", severity:SECURITY_WARNING, xss:TRUE, granularity_regex:"^4(\.1)?$");

