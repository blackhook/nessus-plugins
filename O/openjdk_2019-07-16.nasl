#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151215);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-2745",
    "CVE-2019-2762",
    "CVE-2019-2766",
    "CVE-2019-2769",
    "CVE-2019-2786",
    "CVE-2019-2816",
    "CVE-2019-2818",
    "CVE-2019-2821",
    "CVE-2019-2842",
    "CVE-2019-7317"
  );
  script_xref(name:"IAVA", value:"2019-A-0164-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"OpenJDK 7 <= 7u221 / 8 <= 8u212 / 11.0.0 <= 11.0.3 / 12.0.0 <= 12.0.1 Multiple Vulnerabilities (2019-07-16)");

  script_set_attribute(attribute:"synopsis", value:
"OpenJDK is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenJDK installed on the remote host is prior to 7 <= 7u221 / 8 <= 8u212 / 11.0.0 <= 11.0.3 / 12.0.0 <=
12.0.1. It is, therefore, affected by multiple vulnerabilities as referenced in the 2019-07-16 advisory.

Please Note: Java CVEs do not always include OpenJDK versions, but are confirmed separately by Tenable using the patch
versions from the referenced OpenJDK security advisory.

  - png_image_free in png.c in libpng 1.6.x before 1.6.37 has a use-after-free because png_image_free_function
    is called under png_safe_execute. (CVE-2019-7317)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: JSSE). Supported versions that are
    affected are Java SE: 11.0.3 and 12.0.1. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via TLS to compromise Java SE. Successful attacks require human interaction
    from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    access to critical data or complete access to all Java SE accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). CVSS 3.0 Base Score 5.3 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N). (CVE-2019-2821)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Utilities).
    Supported versions that are affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE Embedded:
    8u211. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 5.3 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2019-2762, CVE-2019-2769)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Security). Supported versions that
    are affected are Java SE: 7u221, 8u212 and 11.0.3. Difficult to exploit vulnerability allows
    unauthenticated attacker with logon to the infrastructure where Java SE executes to compromise Java SE.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Java SE accessible data. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through
    a web service which supplies data to the APIs. CVSS 3.0 Base Score 5.1 (Confidentiality impacts). CVSS
    Vector: (CVSS:3.0/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N). (CVE-2019-2745)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Networking).
    Supported versions that are affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE Embedded:
    8u211. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Java SE, Java SE Embedded accessible data as well
    as unauthorized read access to a subset of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N). (CVE-2019-2816)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: JCE). The supported version that
    is affected is Java SE: 8u212. Difficult to exploit vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java SE. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 3.7 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L). (CVE-2019-2842)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Security).
    Supported versions that are affected are Java SE: 8u212, 11.0.3 and 12.0.1; Java SE Embedded: 8u211.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. CVSS 3.0 Base Score 3.4 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N). (CVE-2019-2786)

  - Vulnerability in the Java SE component of Oracle Java SE (subcomponent: Security). Supported versions that
    are affected are Java SE: 11.0.3 and 12.0.1. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via multiple protocols to compromise Java SE. Successful attacks require
    human interaction from a person other than the attacker. Successful attacks of this vulnerability can
    result in unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability
    applies to Java deployments, typically in clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that comes from the
    internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java
    deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). CVSS 3.0 Base Score 3.1 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N). (CVE-2019-2818)

  - Vulnerability in the Java SE, Java SE Embedded component of Oracle Java SE (subcomponent: Networking).
    Supported versions that are affected are Java SE: 7u221, 8u212, 11.0.3 and 12.0.1; Java SE Embedded:
    8u211. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized read
    access to a subset of Java SE, Java SE Embedded accessible data. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets
    (in Java SE 8), that load and run untrusted code (e.g., code that comes from the internet) and rely on the
    Java sandbox for security. This vulnerability can also be exploited by using APIs in the specified
    Component, e.g., through a web service which supplies data to the APIs. CVSS 3.0 Base Score 3.1
    (Confidentiality impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N). (CVE-2019-2766)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://openjdk.java.net/groups/vulnerability/advisories/2019-07-16");
  script_set_attribute(attribute:"solution", value:
"Upgrade to an OpenJDK version greater than 7u221 / 8u212 / 11.0.3 / 12.0.1");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2821");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:openjdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adoptopenjdk_nix_installed.nbin", "adoptopenjdk_win_installed.nbin", "openjdk_win_installed.nbin", "openjdk_nix_installed.nbin");
  script_require_keys("installed_sw/Java");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_list = [
        'OpenJDK Java',
        'AdoptOpenJDK'
];

var app_info = vcf::java::get_app_info(app:app_list);

var constraints = [
  { 'min_version' : '7.0.0', 'max_version' : '7.0.221', 'fixed_display' : 'Upgrade to a version greater than 7u221' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.212', 'fixed_display' : 'Upgrade to a version greater than 8u212' },
  { 'min_version' : '11.0.0', 'max_version' : '11.0.3', 'fixed_display' : 'Upgrade to a version greater than 11.0.3' },
  { 'min_version' : '12.0.0', 'max_version' : '12.0.1', 'fixed_display' : 'Upgrade to a version greater than 12.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
