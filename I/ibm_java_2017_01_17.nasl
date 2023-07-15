#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160374);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_cve_id(
    "CVE-2016-2183",
    "CVE-2016-5546",
    "CVE-2016-5547",
    "CVE-2016-5548",
    "CVE-2016-5549",
    "CVE-2016-5552",
    "CVE-2017-3231",
    "CVE-2017-3241",
    "CVE-2017-3252",
    "CVE-2017-3253",
    "CVE-2017-3259",
    "CVE-2017-3260",
    "CVE-2017-3261",
    "CVE-2017-3272",
    "CVE-2017-3289"
  );
  script_xref(name:"IAVA", value:"2017-A-0021-S");
  script_xref(name:"IAVA", value:"2016-A-0262-S");

  script_name(english:"IBM Java 6.0 < 6.0.16.41 / 6.1 < 6.1.8.41 / 7.0 < 7.0.10.1 / 7.1 < 7.1.4.1 / 8.0 < 8.0.4.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 6.0 < 6.0.16.41 / 6.1 < 6.1.8.41 / 7.0 < 7.0.10.1 / 7.1
< 7.1.4.1 / 8.0 < 8.0.4.1. It is, therefore, affected by multiple vulnerabilities as referenced in the Oracle January 17
2017 CPU advisory.

  - The DES and Triple DES ciphers, as used in the TLS, SSH, and IPSec protocols and other protocols and
    products, have a birthday bound of approximately four billion blocks, which makes it easier for remote
    attackers to obtain cleartext data via a birthday attack against a long-duration encrypted session, as
    demonstrated by an HTTPS session using Triple DES in CBC mode, aka a Sweet32 attack. (CVE-2016-2183)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Libraries). Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded:
    8u111; JRockit: R28.3.12. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Java SE, Java SE Embedded, JRockit accessible data. Note: Applies to client and server deployment of Java.
    This vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java
    applets. It can also be exploited by supplying data to APIs in the specified Component without using
    sandboxed Java Web Start applications or sandboxed Java applets, such as through a web service.
    (CVE-2016-5546)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Libraries). Supported versions that are affected are Java SE: 7u121 and 8u112; Java SE Embedded: 8u111;
    JRockit: R28.3.12. Easily exploitable vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of
    Java SE, Java SE Embedded, JRockit. Note: Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2016-5547)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Libraries).
    Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized access to critical
    data or complete access to all Java SE, Java SE Embedded accessible data. Note: This vulnerability applies
    to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that
    load and run only trusted code (e.g., code installed by an administrator). (CVE-2016-5548)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Libraries).
    Supported versions that are affected are Java SE: 7u121 and 8u112; Java SE Embedded: 8u111. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized access to critical
    data or complete access to all Java SE, Java SE Embedded accessible data. Note: This vulnerability applies
    to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java
    applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java
    sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that
    load and run only trusted code (e.g., code installed by an administrator). (CVE-2016-5549)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent:
    Networking). Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded:
    8u111; JRockit: R28.3.12. Easily exploitable vulnerability allows unauthenticated attacker with network
    access via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of Java SE, Java SE
    Embedded, JRockit accessible data. Note: Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2016-5552)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Networking).
    Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker. Successful attacks of this vulnerability can result in unauthorized read access to a
    subset of Java SE, Java SE Embedded accessible data. Note: This vulnerability applies to Java deployments,
    typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability does not apply to Java deployments, typically in servers, that load and run
    only trusted code (e.g., code installed by an administrator). (CVE-2017-3231, CVE-2017-3261)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: RMI).
    Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111;
    JRockit: R28.3.12. Difficult to exploit vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. While the vulnerability is in
    Java SE, Java SE Embedded, JRockit, attacks may significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of Java SE, Java SE Embedded, JRockit. Note: This
    vulnerability can only be exploited by supplying data to APIs in the specified Component without using
    Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service.
    (CVE-2017-3241)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: JAAS).
    Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111;
    JRockit: R28.3.12. Difficult to exploit vulnerability allows low privileged attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks require human
    interaction from a person other than the attacker and while the vulnerability is in Java SE, Java SE
    Embedded, JRockit, attacks may significantly impact additional products. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Java SE, Java SE Embedded, JRockit accessible data. Note: Applies to client and server deployment of Java.
    This vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java
    applets. It can also be exploited by supplying data to APIs in the specified Component without using
    sandboxed Java Web Start applications or sandboxed Java applets, such as through a web service.
    (CVE-2017-3252)

  - Vulnerability in the Java SE, Java SE Embedded, JRockit component of Oracle Java SE (subcomponent: 2D).
    Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111;
    JRockit: R28.3.12. Easily exploitable vulnerability allows unauthenticated attacker with network access
    via multiple protocols to compromise Java SE, Java SE Embedded, JRockit. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of Java SE, Java SE Embedded, JRockit. Note: Applies to client and server deployment of Java. This
    vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java applets.
    It can also be exploited by supplying data to APIs in the specified Component without using sandboxed Java
    Web Start applications or sandboxed Java applets, such as through a web service. (CVE-2017-3253)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Deployment). Supported versions
    that are affected are Java SE: 6u131, 7u121 and 8u112. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Java SE. Successful
    attacks of this vulnerability can result in unauthorized read access to a subset of Java SE accessible
    data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java
    Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes
    from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-3259)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: AWT). Supported versions that are
    affected are Java SE: 7u121 and 8u112. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE. Successful attacks require human
    interaction from a person other than the attacker and while the vulnerability is in Java SE, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in takeover
    of Java SE. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed
    Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to
    Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2017-3260)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Libraries).
    Supported versions that are affected are Java SE: 6u131, 7u121 and 8u112; Java SE Embedded: 8u111. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE,
    Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2017-3272)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Hotspot).
    Supported versions that are affected are Java SE: 7u121 and 8u112; Java SE Embedded: 8u111. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE,
    Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2017-3289)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92480");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92481");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92482");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92483");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92484");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92485");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92486");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92487");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92488");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92489");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92490");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV92898");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV93009");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IV93010");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_January_17_2017_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aafe539c");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle January 17 2017 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3289");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
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
  { 'min_version' : '6.0.0', 'fixed_version' : '6.0.16.41' },
  { 'min_version' : '6.1.0', 'fixed_version' : '6.1.8.41' },
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.1' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.1' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.4.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
