#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102587);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-7674");
  script_bugtraq_id(100280);

  script_name(english:"Apache Tomcat 7.0.41 < 7.0.79 Cache Poisoning Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a cache poisoning
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Tomcat installed on the remote host is 7.0.41
or later but prior to 7.0.79. It is, therefore, affected by a flaw in
the CORS filter where the HTTP Vary header is not properly added. This
allows a remote attacker to conduct client-side and server-side cache
poisoning attacks.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.79
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a070de3e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 7.0.79 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7674");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/18");

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

tomcat_check_version(fixed:"7.0.79", min:"7.0.41", severity:SECURITY_WARNING, granularity_regex:"^7(\.0)?$");
