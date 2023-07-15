#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160357);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2018-2783",
    "CVE-2018-2790",
    "CVE-2018-2794",
    "CVE-2018-2795",
    "CVE-2018-2796",
    "CVE-2018-2797",
    "CVE-2018-2798",
    "CVE-2018-2799",
    "CVE-2018-2800",
    "CVE-2018-2814",
    "CVE-2018-2826"
  );
  script_xref(name:"IAVA", value:"2018-A-0119-S");

  script_name(english:"IBM Java 6.0 < 6.0.16.65 / 6.1 < 6.1.8.65 / 7.0 < 7.0.10.25 / 7.1 < 7.1.4.25 / 8.0 < 8.0.5.15 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.65 / 6.1 < 6.1.8.65 / 7.0 < 7.0.10.25 /
7.1 < 7.1.4.25 / 8.0 < 8.0.5.15. It is, therefore, affected by multiple vulnerabilities as referenced in the Oracle
April 17 2018 CPU advisory.

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Security). Supported versions that are affected are Java SE: 6u181, 7u161 and 8u152; Java SE Embedded:
    8u152; JRockit: R28.3.17. Difficult to exploit vulnerability allows unauthenticated attacker with network
    access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Java SE, Java SE Embedded, JRockit accessible data as well as unauthorized access to critical data or
    complete access to all Java SE, Java SE Embedded, JRockit accessible data. Note: Applies to client and
    server deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start
    applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as
    through a web service. (CVE-2018-2783)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Security).
    Supported versions that are affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded: 8u161.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2018-2790)

  - Vulnerability in the Java SE, JRockit component of Oracle Java SE (subcomponent: Security). Supported
    versions that are affected are Java SE: 6u181, 7u171, 8u162, 10 and JRockit: R28.3.17. Difficult to
    exploit vulnerability allows unauthenticated attacker with logon to the infrastructure where Java SE,
    JRockit executes to compromise Java SE, JRockit. Successful attacks require human interaction from a
    person other than the attacker and while the vulnerability is in Java SE, JRockit, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in takeover
    of Java SE, JRockit. Note: Applies to client and server deployment of Java. This vulnerability can be
    exploited through sandboxed Java Web Start applications and sandboxed Java applets. It can also be
    exploited by supplying data to APIs in the specified Component without using sandboxed Java Web Start
    applications or sandboxed Java applets, such as through a web service. (CVE-2018-2794)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Security). Supported versions that are affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded:
    8u161; JRockit: R28.3.17. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded, JRockit. Note: Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2018-2795)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Concurrency). Supported versions that are affected are Java SE: 7u171, 8u162 and 10; Java SE Embedded:
    8u161; JRockit: R28.3.17. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded, JRockit. Note: Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2018-2796)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JMX).
    Supported versions that are affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded: 8u161;
    JRockit: R28.3.17. Easily exploitable vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded, JRockit. Note: Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2018-2797)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: AWT).
    Supported versions that are affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded: 8u161;
    JRockit: R28.3.17. Easily exploitable vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded, JRockit. Note: Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2018-2798)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JAXP).
    Supported versions that are affected are Java SE: 7u171, 8u162 and 10; Java SE Embedded: 8u161; JRockit:
    R28.3.17. Easily exploitable vulnerability allows unauthenticated attacker with network access via
    multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded, JRockit. Note: Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2018-2799)

  - Vulnerability in the Java SE, JRockit component of Oracle Java SE (subcomponent: RMI). Supported versions
    that are affected are Java SE: 6u181, 7u171 and 8u162; JRockit: R28.3.17. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Java SE, JRockit. Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to
    some of Java SE, JRockit accessible data as well as unauthorized read access to a subset of Java SE,
    JRockit accessible data. Note: This vulnerability can only be exploited by supplying data to APIs in the
    specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as
    through a web service. (CVE-2018-2800)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Hotspot).
    Supported versions that are affected are Java SE: 6u181, 7u171, 8u162 and 10; Java SE Embedded: 8u161.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in takeover
    of Java SE, Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability
    does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code
    installed by an administrator). (CVE-2018-2814)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Libraries). The supported version
    that is affected is Java SE: 10. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE. Successful attacks require human interaction
    from a person other than the attacker and while the vulnerability is in Java SE, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2018-2826)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06342");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06343");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06344");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06345");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06346");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06347");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06348");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06349");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ06351");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_April_17_2018_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a34c814d");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle April 17 2018 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2783");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/17");
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
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.65' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.65' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.25' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.25' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5.15' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
