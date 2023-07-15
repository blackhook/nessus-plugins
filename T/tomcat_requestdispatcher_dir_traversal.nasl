#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(39447);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2008-5515");
  script_bugtraq_id(35263);
  script_xref(name:"Secunia", value:"35326");

  script_name(english:"Apache Tomcat RequestDispatcher Directory Traversal Arbitrary File Access");
  script_summary(english:"Checks the version retrieved from a Tomcat error page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote host is
running a vulnerable version of Apache Tomcat. Due to a bug in a
RequestDispatcher API, target paths are normalized before the query
string is removed, which could result in directory traversal attacks.
This allows a remote attacker to view files outside of the web
application's root.");
  # http://www.fujitsu.com/global/support/products/software/security/products-f/interstage-200902e.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5bdbccf");
  script_set_attribute(attribute:"see_also", value:"https://marc.info/?l=tomcat-user&m=124449799021571&w=2");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-6.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-5.html");
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to versions 6.0.20 / 5.5.28 / 4.1.40 or later. Alternatively,
apply the patches referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-5515");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("installed_sw/Apache Tomcat");
  exit(0);
}


include("tomcat_version.inc");

tomcat_check_version(fixed:make_list("6.0.20", "5.5.28", "4.1.40"), severity:SECURITY_WARNING, granularity_regex:"^(6(\.0)?|5(\.5)?|4(\.1)?)$");
