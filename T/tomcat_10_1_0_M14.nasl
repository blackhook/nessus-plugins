#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165511);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/02");

  script_cve_id("CVE-2021-43980");

  script_name(english:"Apache Tomcat 10.1.0.M1 < 10.1.0.M14 vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 10.1.0.M14. It is, therefore, affected by a vulnerability
as referenced in the fixed_in_apache_tomcat_10.1.0-m14_security-10 advisory.

  - The simplified implementation of blocking reads and writes introduced in Tomcat 10 and back-ported to
    Tomcat 9.0.47 onwards exposed a long standing (but extremely hard to trigger) concurrency bug that could
    cause client connections to share an Http11Processor instance resulting in responses, or part responses,
    to be received by the wrong client. (CVE-2021-43980)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/apache/tomcat/commit/9651b83a1d04583791525e5f0c4c9089f678d9fc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22b0fd1f");
  # https://tomcat.apache.org/security-10.html#Fixed_in_Apache_Tomcat_10.1.0-M14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9717459f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 10.1.0.M14 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43980");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '10.1.0.M14', min:'10.1.0.M1', severity:SECURITY_NOTE, granularity_regex: "^(10(\.1(\.0)?)?)$");
