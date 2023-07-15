#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(121125);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/24");

  script_cve_id(
    "CVE-2015-5345",
    "CVE-2015-5346",
    "CVE-2015-5351",
    "CVE-2016-0706",
    "CVE-2016-0714",
    "CVE-2016-0763"
  );

  script_name(english:"Apache Tomcat < 9.0.0.M3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Apache Tomcat
instance listening on the remote host is prior to 9.0.0.M3. It is,
therefore, affected by multiple vulnerabilities:

  - An information disclosure vulnerability exists due to
    a failure to enforce access restrictions when handling
    directory requests that are missing trailing slashes. An
    unauthenticated, remote attacker can exploit this to
    enumerate valid directories. (CVE-2015-5345)

  - A flaw exists due to a failure to invalidate a previous
    session ID when assigning an ID to a new session. An
    attacker can exploit this, via a crafted request that
    uses the requestedSessionSSL field to fixate the session
    ID, to ensure that the user authenticates with a known
    session ID, allowing the session to be subsequently
    hijacked. (CVE-2015-5346)

  - An information disclosure vulnerability exists in the
    Manager and Host Manager web applications due to a flaw
    in the index page when issuing redirects in response to
    unauthenticated requests for the root directory of the
    application. An unauthenticated, remote attacker can
    exploit this to gain access to the XSRF token
    information stored in the index page. (CVE-2015-5351)

  - An information disclosure vulnerability exists that
    allows a specially crafted web application to load the
    StatusManagerServlet. An attacker can exploit this to
    gain unauthorized access to a list of all deployed
    applications and a list of the HTTP request lines for
    all requests currently being processed. (CVE-2016-0706)

  - A security bypass vulnerability exists due to a flaw
    in the StandardManager, PersistentManager, and cluster
    implementations that is triggered when handling
    persistent sessions. An unauthenticated, remote attacker
    can exploit this, via a crafted object in a session, to
    bypass the security manager and execute arbitrary code.
    (CVE-2016-0714)

  - A flaw exists due to the setGlobalContext() method of
    ResourceLinkFactory being accessible to web applications
    even when run under a security manager. An
    unauthenticated, remote attacker can exploit this to
    inject malicious global context, allowing data owned by
    other web applications to be read or written to.
    (CVE-2016-0763)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77a5c04a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Tomcat version 9.0.0.M3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-5351");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-0714");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tomcat_error_version.nasl", "tomcat_win_installed.nbin", "apache_tomcat_nix_installed.nbin");
  script_require_keys("installed_sw/Apache Tomcat");

  exit(0);
}

include('tomcat_version.inc');

tomcat_check_version(fixed:"9.0.0.M3", min:"9.0.0", severity:SECURITY_WARNING, granularity_regex:"^9(\.0)?$");

