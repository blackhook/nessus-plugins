#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-34.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164434);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/08");

  script_cve_id(
    "CVE-2021-25122",
    "CVE-2021-25329",
    "CVE-2021-30639",
    "CVE-2021-30640",
    "CVE-2021-33037",
    "CVE-2021-42340",
    "CVE-2022-34305"
  );
  script_xref(name:"IAVA", value:"2022-A-0398-S");

  script_name(english:"GLSA-202208-34 : Apache Tomcat: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-34 (Apache Tomcat: Multiple Vulnerabilities)

  - When responding to new h2c connection requests, Apache Tomcat versions 10.0.0-M1 to 10.0.0, 9.0.0.M1 to
    9.0.41 and 8.5.0 to 8.5.61 could duplicate request headers and a limited amount of request body from one
    request to another meaning user A and user B could both see the results of user A's request.
    (CVE-2021-25122)

  - The fix for CVE-2020-9484 was incomplete. When using Apache Tomcat 10.0.0-M1 to 10.0.0, 9.0.0.M1 to
    9.0.41, 8.5.0 to 8.5.61 or 7.0.0. to 7.0.107 with a configuration edge case that was highly unlikely to be
    used, the Tomcat instance was still vulnerable to CVE-2020-9494. Note that both the previously published
    prerequisites for CVE-2020-9484 and the previously published mitigations for CVE-2020-9484 also apply to
    this issue. (CVE-2021-25329)

  - A vulnerability in Apache Tomcat allows an attacker to remotely trigger a denial of service. An error
    introduced as part of a change to improve error handling during non-blocking I/O meant that the error flag
    associated with the Request object was not reset between requests. This meant that once a non-blocking I/O
    error occurred, all future requests handled by that request object would fail. Users were able to trigger
    non-blocking I/O errors, e.g. by dropping a connection, thereby creating the possibility of triggering a
    DoS. Applications that do not use non-blocking I/O are not exposed to this vulnerability. This issue
    affects Apache Tomcat 10.0.3 to 10.0.4; 9.0.44; 8.5.64. (CVE-2021-30639)

  - A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of
    a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue
    affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65. (CVE-2021-30640)

  - Apache Tomcat 10.0.0-M1 to 10.0.6, 9.0.0.M1 to 9.0.46 and 8.5.0 to 8.5.66 did not correctly parse the HTTP
    transfer-encoding request header in some circumstances leading to the possibility to request smuggling
    when used with a reverse proxy. Specifically: - Tomcat incorrectly ignored the transfer encoding header if
    the client declared it would only accept an HTTP/1.0 response; - Tomcat honoured the identify encoding;
    and - Tomcat did not ensure that, if present, the chunked encoding was the final encoding.
    (CVE-2021-33037)

  - The fix for bug 63362 present in Apache Tomcat 10.1.0-M1 to 10.1.0-M5, 10.0.0-M1 to 10.0.11, 9.0.40 to
    9.0.53 and 8.5.60 to 8.5.71 introduced a memory leak. The object introduced to collect metrics for HTTP
    upgrade connections was not released for WebSocket connections once the connection was closed. This
    created a memory leak that, over time, could lead to a denial of service via an OutOfMemoryError.
    (CVE-2021-42340)

  - In Apache Tomcat 10.1.0-M1 to 10.1.0-M16, 10.0.0-M1 to 10.0.22, 9.0.30 to 9.0.64 and 8.5.50 to 8.5.81 the
    Form authentication example in the examples web application displayed user provided data without
    filtering, exposing a XSS vulnerability. (CVE-2022-34305)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-34");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=773571");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=801916");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=818160");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=855971");
  script_set_attribute(attribute:"solution", value:
"All Apache Tomcat 10.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-servers/tomcat-10.0.23:10
        
All Apache Tomcat 9.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-servers/tomcat-9.0.65:9
        
All Apache Tomcat 8.5.x users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-servers/tomcat-8.5.82:8.5");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30640");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-25122");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "www-servers/tomcat",
    'unaffected' : make_list("ge 10.0.23", "lt 10.0.0"),
    'vulnerable' : make_list("lt 10.0.23")
  },
  {
    'name' : "www-servers/tomcat",
    'unaffected' : make_list("ge 8.5.82", "lt 8.0.0"),
    'vulnerable' : make_list("lt 8.5.82")
  },
  {
    'name' : "www-servers/tomcat",
    'unaffected' : make_list("ge 9.0.65", "lt 9.0.0"),
    'vulnerable' : make_list("lt 9.0.65")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}

# This plugin has a different number of unaffected and vulnerable versions for
# one or more packages. To ensure proper detection, a separate line should be 
# used for each fixed/vulnerable version pair.

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache Tomcat");
}
