#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(53323);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2011-1183",
    "CVE-2011-1184",
    "CVE-2011-1475",
    "CVE-2011-5062",
    "CVE-2011-5063",
    "CVE-2011-5064"
  );
  script_bugtraq_id(47196, 47199, 49762);
  script_xref(name:"SECUNIA", value:"43684");

  script_name(english:"Apache Tomcat 7.x < 7.0.12 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.x listening on the remote host is prior to 7.0.12. It is,
therefore, affected by multiple vulnerabilities :

  - A fix for CVE-2011-1088 introduced a security bypass
    vulnerability. If login configuration data is absent
    from the 'web.xml' file and a web application is
    marked as 'metadata-complete', security constraints are
    ignored and may be bypassed by an attacker. Please note
    this vulnerability only affects version 7.0.11 of
    Tomcat. (CVE-2011-1183)

  - Several weaknesses were found in the HTTP Digest
    authentication implementation. The issues are as
    follows: replay attacks are possible, server nonces
    are not checked, client nonce counts are not checked,
    'quality of protection' (qop) values are not checked,
    realm values are not checked, and the server secret is
    a hard-coded, known string. The effect of these issues
    is that Digest authentication is no stronger than Basic
    authentication. (CVE-2011-1184, CVE-2011-5062,
    CVE-2011-5063, CVE-2011-5064)

  - Updates to the HTTP BIO connector, in support of
    Servlet 3.0 asynchronous requests, fail to completely
    handle HTTP pipelining. Sensitive information may be
    disclosed because responses from the server can be
    improperly returned to the wrong request and possibly
    to the wrong user. (CVE-2011-1475)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.12_(released_6_Apr_2011)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?343187a6");
  script_set_attribute(attribute:"see_also", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=50928");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1087643");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.12 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/07");

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

tomcat_check_version(fixed:"7.0.12", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");

