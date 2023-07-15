#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(54301);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2011-1582");
  script_bugtraq_id(47886);
  script_xref(name:"SECUNIA", value:"44612");

  script_name(english:"Apache Tomcat 7.0.12 / 7.0.13 Security Constraint Bypass");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a security constraint bypass
vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of Apache
Tomcat 7.0.12 or 7.0.13 listening on the remote host is affected
by a security constraint bypass vulnerability.

Fixes for CVE-2011-1088 and CVE-2011-1183 introduced an error in
'core/StandardWrapper.java' which allows an incorrect class loader to
be used. The effect of this is that security constraints configured
through annotations are ignored on the initial request to a servlet.
However, further requests are secured properly.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.14_%28released_12_May_2011%29
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a1f0794");
  script_set_attribute(attribute:"see_also", value:"http://svn.apache.org/viewvc?view=revision&revision=1100832");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/bugtraq/2011/May/134");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.14 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/18");

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

tomcat_check_version(fixed:"7.0.14", min:"7.0.0", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");

