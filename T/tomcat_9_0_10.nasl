#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(176310);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/24");

  script_cve_id("CVE-2018-8034", "CVE-2018-8037");

  script_name(english:"Apache Tomcat 9.0.0.M1 < 9.0.10 multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Tomcat installed on the remote host is prior to 9.0.10. It is, therefore, affected by multiple
vulnerabilities as referenced in the fixed_in_apache_tomcat_9.0.10_security-9 advisory.

  - The host name verification when using TLS with the WebSocket client was missing. It is now enabled by
    default. Versions Affected: Apache Tomcat 9.0.0.M1 to 9.0.9, 8.5.0 to 8.5.31, 8.0.0.RC1 to 8.0.52, and
    7.0.35 to 7.0.88. (CVE-2018-8034)

  - If an async request was completed by the application at the same time as the container triggered the async
    timeout, a race condition existed that could result in a user seeing a response intended for a different
    user. An additional issue was present in the NIO and NIO2 connectors that did not correctly track the
    closure of the connection when an async request was completed by the application and timed out by the
    container at the same time. This could also result in a user seeing a response intended for another user.
    Versions Affected: Apache Tomcat 9.0.0.M9 to 9.0.9 and 8.5.5 to 8.5.31. (CVE-2018-8037)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1833757");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1833825");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1833831");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1837530");
  script_set_attribute(attribute:"see_also", value:"https://svn.apache.org/viewvc?view=rev&rev=1833906");
  # https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f242e95");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.10 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed: '9.0.10', min:'9.0.0.M1', severity:SECURITY_WARNING, granularity_regex: "^9(\.0)?$");
