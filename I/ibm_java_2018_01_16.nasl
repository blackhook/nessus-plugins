#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160344);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/29");

  script_cve_id(
    "CVE-2018-2579",
    "CVE-2018-2582",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2602",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2633",
    "CVE-2018-2634",
    "CVE-2018-2637",
    "CVE-2018-2638",
    "CVE-2018-2639",
    "CVE-2018-2641",
    "CVE-2018-2657",
    "CVE-2018-2663",
    "CVE-2018-2677",
    "CVE-2018-2678"
  );
  script_xref(name:"IAVA", value:"2018-A-0031-S");

  script_name(english:"IBM Java 6.0 < 6.0.16.60 / 6.1 < 6.1.8.60 / 7.0 < 7.0.10.20 / 7.1 < 7.1.4.20 / 8.0 < 8.0.5.10 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.60 / 6.1 < 6.1.8.60 / 7.0 < 7.0.10.20 /
7.1 < 7.1.4.20 / 8.0 < 8.0.5.10. It is, therefore, affected by multiple vulnerabilities as referenced in the Oracle
January 16 2018 CPU advisory.

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Libraries). Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE
    Embedded: 8u151; JRockit: R28.3.16. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of Java SE, Java SE
    Embedded, JRockit accessible data. Note: This vulnerability applies to client and server deployment of
    Java. This vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java
    applets. It can also be exploited by supplying data to APIs in the specified Component without using
    sandboxed Java Web Start applications or sandboxed Java applets, such as through a web service.
    (CVE-2018-2579)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Hotspot).
    Supported versions that are affected are Java SE: 8u152 and 9.0.1; Java SE Embedded: 8u151. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized creation, deletion
    or modification access to critical data or all Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to client and server deployment of Java. This vulnerability can be exploited through
    sandboxed Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying
    data to APIs in the specified Component without using sandboxed Java Web Start applications or sandboxed
    Java applets, such as through a web service. (CVE-2018-2582)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: LDAP).
    Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151;
    JRockit: R28.3.16. Easily exploitable vulnerability allows low privileged attacker with network access via
    multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized read access to a subset of Java SE, Java SE Embedded, JRockit
    accessible data. Note: This vulnerability applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2018-2588)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JNDI).
    Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151;
    JRockit: R28.3.16. Difficult to exploit vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of Java SE, Java SE
    Embedded, JRockit accessible data and unauthorized ability to cause a partial denial of service (partial
    DOS) of Java SE, Java SE Embedded, JRockit. Note: This vulnerability applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2018-2599)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: I18n). Supported
    versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151. Difficult
    to exploit vulnerability allows unauthenticated attacker with logon to the infrastructure where Java SE,
    Java SE Embedded executes to compromise Java SE, Java SE Embedded. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Java SE, Java SE Embedded accessible data as well
    as unauthorized read access to a subset of Java SE, Java SE Embedded accessible data and unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2018-2602)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Libraries). Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE
    Embedded: 8u151; JRockit: R28.3.16. Easily exploitable vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial
    DOS) of Java SE, Java SE Embedded, JRockit. Note: This vulnerability applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2018-2603)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JCE).
    Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151;
    JRockit: R28.3.16. Difficult to exploit vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized access to critical data or complete access to all Java SE, Java
    SE Embedded, JRockit accessible data. Note: This vulnerability applies to client and server deployment of
    Java. This vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java
    applets. It can also be exploited by supplying data to APIs in the specified Component without using
    sandboxed Java Web Start applications or sandboxed Java applets, such as through a web service.
    (CVE-2018-2618)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JNDI).
    Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151;
    JRockit: R28.3.16. Difficult to exploit vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks require human
    interaction from a person other than the attacker and while the vulnerability is in Java SE, Java SE
    Embedded, JRockit, attacks may significantly impact additional products. Successful attacks of this
    vulnerability can result in takeover of Java SE, Java SE Embedded, JRockit. Note: This vulnerability
    applies to client and server deployment of Java. This vulnerability can be exploited through sandboxed
    Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying data to APIs
    in the specified Component without using sandboxed Java Web Start applications or sandboxed Java applets,
    such as through a web service. (CVE-2018-2633)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: JGSS). Supported
    versions that are affected are Java SE: 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. While the vulnerability is in Java SE, Java SE Embedded, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all Java SE, Java SE Embedded accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2018-2634)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JMX).
    Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151;
    JRockit: R28.3.16. Difficult to exploit vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Java SE, Java SE Embedded, JRockit accessible data as well as unauthorized access to critical data or
    complete access to all Java SE, Java SE Embedded, JRockit accessible data. Note: This vulnerability can
    only be exploited by supplying data to APIs in the specified Component without using Untrusted Java Web
    Start applications or Untrusted Java applets, such as through a web service. (CVE-2018-2637)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Deployment). Supported versions
    that are affected are Java SE: 8u152 and 9.0.1. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE. Successful attacks require
    human interaction from a person other than the attacker and while the vulnerability is in Java SE, attacks
    may significantly impact additional products. Successful attacks of this vulnerability can result in
    takeover of Java SE. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2018-2638, CVE-2018-2639)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: AWT). Supported
    versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151. Difficult
    to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all Java SE, Java SE Embedded accessible data. Note:
    This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2018-2641)

  - Vulnerability in the Java SE, JRockit component of Oracle Java SE (subcomponent: Serialization). Supported
    versions that are affected are Java SE: 6u171 and 7u161; JRockit: R28.3.16. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Java SE, JRockit. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Java SE, JRockit. Note: This vulnerability can only be
    exploited by supplying data to APIs in the specified Component without using Untrusted Java Web Start
    applications or Untrusted Java applets, such as through a web service. (CVE-2018-2657)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Libraries). Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE
    Embedded: 8u151; JRockit: R28.3.16. Easily exploitable vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks
    require human interaction from a person other than the attacker. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE
    Embedded, JRockit. Note: This vulnerability applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2018-2663)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: AWT). Supported
    versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a
    partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This vulnerability applies to
    Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that
    load and run only trusted code (e.g., code installed by an administrator). (CVE-2018-2677)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JNDI).
    Supported versions that are affected are Java SE: 6u171, 7u161, 8u152 and 9.0.1; Java SE Embedded: 8u151;
    JRockit: R28.3.16. Easily exploitable vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded,
    JRockit. Note: This vulnerability applies to client and server deployment of Java. This vulnerability can
    be exploited through sandboxed Java Web Start applications and sandboxed Java applets. It can also be
    exploited by supplying data to APIs in the specified Component without using sandboxed Java Web Start
    applications or sandboxed Java applets, such as through a web service. (CVE-2018-2678)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04031");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04034");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04036");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04037");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04038");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04039");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04040");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04041");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04042");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04043");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04044");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04045");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04046");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04047");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04051");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04052");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ04053");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_January_16_2018_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d150f57");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle January 16 2018 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2639");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_java_nix_installed.nbin", "ibm_java_win_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['IBM Java'];
var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.60' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.60' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.20' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.20' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
