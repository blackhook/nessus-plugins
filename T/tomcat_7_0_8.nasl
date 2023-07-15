#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(51987);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-0534");
  script_bugtraq_id(46164);
  script_xref(name:"SECUNIA", value:"43194");

  script_name(english:"Apache Tomcat < 6.0.32 / 7.0.8 NIO Connector DoS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat listening on the remote host is prior to 6.0.32 or 7.0.8. It
is, therefore, affected by a denial of service vulnerability. An
error, involving the NIO HTTP connector, exists such that the limit
'maxHttpHeaderSize' is not enforced thereby allowing a denial of
service condition when memory is exhausted.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.32
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fba1931");
  # https://www.securityfocus.com/archive/1/archive/1/516214/100/0/threaded
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eacc755c");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.8_(released_5_Feb_2011)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?daf049a2");
  script_set_attribute(attribute:"solution", value:
"Update Apache Tomcat to version 6.0.32 / 7.0.8 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0534");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/15");

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

tomcat_check_version(fixed:make_list("7.0.8", "6.0.32"), severity:SECURITY_WARNING, granularity_regex:"^[67](\.0)?$");

