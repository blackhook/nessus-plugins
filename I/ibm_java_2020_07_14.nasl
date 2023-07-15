#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160372);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id(
    "CVE-2020-14556",
    "CVE-2020-14577",
    "CVE-2020-14578",
    "CVE-2020-14579",
    "CVE-2020-14581",
    "CVE-2020-14583",
    "CVE-2020-14593",
    "CVE-2020-14621"
  );
  script_xref(name:"IAVA", value:"2020-A-0322-S");

  script_name(english:"IBM Java 7.0 < 7.0.10.70 / 7.1 < 7.1.4.70 / 8.0 < 8.0.6.15 Multiple Vulnerabilities (Jul 14, 2020)");

  script_set_attribute(attribute:"synopsis", value:
"IBM Java is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Java installed on the remote host is prior to 7.0 < 7.0.10.70 / 7.1 < 7.1.4.70 / 8.0 < 8.0.6.15. It
is, therefore, affected by multiple vulnerabilities as referenced in the Oracle July 14 2020 CPU advisory.

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 8u251, 11.0.7 and 14.0.1; Java SE Embedded: 8u251. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data as well as
    unauthorized read access to a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client
    and server deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start
    applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as
    through a web service. (CVE-2020-14556)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JSSE). Supported
    versions that are affected are Java SE: 7u261, 8u251, 11.0.7 and 14.0.1; Java SE Embedded: 8u251.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via TLS to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2020-14577)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u261 and 8u251; Java SE Embedded: 8u251. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: Applies to client and
    server deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start
    applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as
    through a web service. (CVE-2020-14578, CVE-2020-14579)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: 2D). Supported
    versions that are affected are Java SE: 8u251, 11.0.7 and 14.0.1; Java SE Embedded: 8u251. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    read access to a subset of Java SE, Java SE Embedded accessible data. Note: Applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2020-14581)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u261, 8u251, 11.0.7 and 14.0.1; Java SE Embedded: 8u251.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in takeover
    of Java SE, Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code
    (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability
    does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code
    installed by an administrator). (CVE-2020-14583)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: 2D). Supported
    versions that are affected are Java SE: 7u261, 8u251, 11.0.7 and 14.0.1; Java SE Embedded: 8u251. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all Java SE, Java SE Embedded accessible data. Note:
    This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2020-14593)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JAXP). Supported
    versions that are affected are Java SE: 7u261, 8u251, 11.0.7 and 14.0.1; Java SE Embedded: 8u251. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability can only be exploited by supplying data to APIs in the specified Component without using
    Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service.
    (CVE-2020-14621)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ26673");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ26674");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ26675");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ26676");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ26677");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ26678");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1IJ26701");
  # https://www.ibm.com/support/pages/java-sdk-security-vulnerabilities#Oracle_July_14_2020_CPU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48659da6");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the Oracle July 14 2020 CPU advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14556");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-14583");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
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
  { 'min_version' : '7.0.0', 'fixed_version' : '7.0.10.70' },
  { 'min_version' : '7.1.0', 'fixed_version' : '7.1.4.70' },
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.6.15' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
