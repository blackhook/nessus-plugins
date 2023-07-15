#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160352);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/26");

  script_cve_id(
    "CVE-2016-9841",
    "CVE-2016-10165",
    "CVE-2017-10281",
    "CVE-2017-10285",
    "CVE-2017-10293",
    "CVE-2017-10295",
    "CVE-2017-10309",
    "CVE-2017-10345",
    "CVE-2017-10346",
    "CVE-2017-10347",
    "CVE-2017-10348",
    "CVE-2017-10349",
    "CVE-2017-10350",
    "CVE-2017-10355",
    "CVE-2017-10356",
    "CVE-2017-10357",
    "CVE-2017-10388"
  );
  script_xref(name:"IAVA", value:"2017-A-0306-S");

  script_name(english:"IBM Java 6.0 < 6.0.16.55 / 6.1 < 6.1.8.55 / 7.0 < 7.0.15.5 / 7.1 < 7.1.5.5 / 8.0 < 8.0.5.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.55 / 6.1 < 6.1.8.55 / 7.0 < 7.0.15.5 / 7.1
< 7.1.5.5 / 8.0 < 8.0.5.5. It is, therefore, affected by multiple vulnerabilities as referenced in the Oracle October 17
2017 CPU advisory.

  - inffast.c in zlib 1.2.8 might allow context-dependent attackers to have unspecified impact by leveraging
    improper pointer arithmetic. (CVE-2016-9841)

  - The Type_MLU_Read function in cmstypes.c in Little CMS (aka lcms2) allows remote attackers to obtain
    sensitive information or cause a denial of service via an image with a crafted ICC profile, which triggers
    an out-of-bounds heap read. (CVE-2016-10165)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Serialization). Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE
    Embedded: 8u144; JRockit: R28.3.15. Easily exploitable vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial
    DOS) of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can be exploited through sandboxed
    Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying data to APIs
    in the specified Component without using sandboxed Java Web Start applications or sandboxed Java applets,
    such as through a web service. (CVE-2017-10281)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: RMI). Supported
    versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE,
    Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2017-10285)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Javadoc). Supported versions that
    are affected are Java SE: 6u161, 7u151, 8u144 and 9. Easily exploitable vulnerability allows
    unauthenticated attacker with network access via HTTP to compromise Java SE. Successful attacks require
    human interaction from a person other than the attacker and while the vulnerability is in Java SE, attacks
    may significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Java SE accessible data as well as unauthorized
    read access to a subset of Java SE accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). (CVE-2017-10293)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Networking). Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE
    Embedded: 8u144; JRockit: R28.3.15. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via HTTP to compromise Java SE, Java SE Embedded, JRockit. While the vulnerability is
    in Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional products. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Java
    SE, Java SE Embedded, JRockit accessible data. Note: This vulnerability can be exploited through sandboxed
    Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying data to APIs
    in the specified Component without using sandboxed Java Web Start applications or sandboxed Java applets,
    such as through a web service. (CVE-2017-10295)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Deployment). Supported versions
    that are affected are Java SE: 8u144 and 9. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE. Successful attacks require
    human interaction from a person other than the attacker and while the vulnerability is in Java SE, attacks
    may significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Java SE accessible data as well as unauthorized
    read access to a subset of Java SE accessible data and unauthorized ability to cause a partial denial of
    service (partial DOS) of Java SE. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). (CVE-2017-10309)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Serialization). Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE
    Embedded: 8u144; JRockit: R28.3.15. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful
    attacks require human interaction from a person other than the attacker. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded, JRockit. Note: This vulnerability can be exploited through sandboxed Java Web
    Start applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as
    through a web service. (CVE-2017-10345)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Hotspot).
    Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in takeover
    of Java SE, Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability
    does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code
    installed by an administrator). (CVE-2017-10346)

  - Vulnerability in the Java SE, JRockit component of Oracle Java SE (subcomponent: Serialization). Supported
    versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, JRockit. Successful attacks of this vulnerability can result in unauthorized ability
    to cause a partial denial of service (partial DOS) of Java SE, JRockit. Note: This vulnerability applies
    to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that
    load and run only trusted code (e.g., code installed by an administrator). (CVE-2017-10347)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Libraries).
    Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-10348)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: JAXP). Supported
    versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-10349)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: JAX-WS).
    Supported versions that are affected are Java SE: 7u151, 8u144 and 9; Java SE Embedded: 8u144. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-10350)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Networking). Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE
    Embedded: 8u144; JRockit: R28.3.15. Easily exploitable vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks
    of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial
    DOS) of Java SE, Java SE Embedded, JRockit. Note: This vulnerability can be exploited through sandboxed
    Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying data to APIs
    in the specified Component without using sandboxed Java Web Start applications or sandboxed Java applets,
    such as through a web service. (CVE-2017-10355)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Security). Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded:
    8u144; JRockit: R28.3.15. Easily exploitable vulnerability allows unauthenticated attacker with logon to
    the infrastructure where Java SE, Java SE Embedded, JRockit executes to compromise Java SE, Java SE
    Embedded, JRockit. Successful attacks of this vulnerability can result in unauthorized access to critical
    data or complete access to all Java SE, Java SE Embedded, JRockit accessible data. Note: This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2017-10356)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Serialization).
    Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from
    the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-10357)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Libraries).
    Supported versions that are affected are Java SE: 6u161, 7u151, 8u144 and 9; Java SE Embedded: 8u144.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via Kerberos to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in takeover of Java SE, Java SE
    Embedded. Note: Applies to the Java SE Kerberos client. (CVE-2017-10388)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://docs.oracle.com/javase/8/docs/technotes/tools/unix/javadoc.html");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01211");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01212");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01213");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01214");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01215");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01216");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01217");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01218");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01219");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01220");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01221");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01222");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01223");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01224");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ01225");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_October_17_2017_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4e1a721");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle October 17 2017 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9841");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:java");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ibm_java_nix_installed.nbin", "ibm_java_win_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = ['IBM Java'];
var app_info = vcf::java::get_app_info(app:app_list);
var os = get_kb_item_or_exit('Host/OS');

if ('solaris' >< tolower(os) || 'mac os' >< tolower(os) || 'hp-ux' >< tolower(os))
{
  var constraints = [
    { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.55' },
    { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.55' },
    { 'min_version' : '7.0.0', 'fixed_version' : '7.0.15.5' },
    { 'min_version' : '7.1.0', 'fixed_version' : '7.1.5.5' },
    { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5.5' }  
  ];
}

else constraints = [
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.55' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.55' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.5' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.15' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.5.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
