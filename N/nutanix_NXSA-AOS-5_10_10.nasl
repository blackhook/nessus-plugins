#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164585);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2018-16871",
    "CVE-2018-16881",
    "CVE-2018-16884",
    "CVE-2019-2945",
    "CVE-2019-2949",
    "CVE-2019-2962",
    "CVE-2019-2964",
    "CVE-2019-2973",
    "CVE-2019-2975",
    "CVE-2019-2978",
    "CVE-2019-2981",
    "CVE-2019-2983",
    "CVE-2019-2987",
    "CVE-2019-2988",
    "CVE-2019-2989",
    "CVE-2019-2992",
    "CVE-2019-2999",
    "CVE-2019-11085",
    "CVE-2019-11811",
    "CVE-2019-14287"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.10.10)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.10.10. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.10.10 advisory.

  - A flaw was found in the Linux kernel's NFS implementation, all versions 3.x and all versions 4.x up to
    4.20. An attacker, who is able to mount an exported NFS filesystem, is able to trigger a null pointer
    dereference by using an invalid NFS sequence. This can panic the machine and deny access to the NFS
    server. Any outstanding disk writes to the NFS server will be lost. (CVE-2018-16871)

  - A denial of service vulnerability was found in rsyslog in the imptcp module. An attacker could send a
    specially crafted message to the imptcp socket, which would cause rsyslog to crash. Versions before 8.27.0
    are vulnerable. (CVE-2018-16881)

  - A flaw was found in the Linux kernel's NFS41+ subsystem. NFS41+ shares mounted in different network
    namespaces at the same time can make bc_svc_process() use wrong back-channel IDs and cause a use-after-
    free vulnerability. Thus a malicious container user can cause a host kernel memory corruption and a system
    panic. Due to the nature of the flaw, privilege escalation cannot be fully ruled out. (CVE-2018-16884)

  - Insufficient input validation in Kernel Mode Driver in Intel(R) i915 Graphics for Linux before version 5.0
    may allow an authenticated user to potentially enable escalation of privilege via local access.
    (CVE-2019-11085)

  - An issue was discovered in the Linux kernel before 5.0.4. There is a use-after-free upon attempted read
    access to /proc/ioports after the ipmi_si module is removed, related to drivers/char/ipmi/ipmi_si_intf.c,
    drivers/char/ipmi/ipmi_si_mem_io.c, and drivers/char/ipmi/ipmi_si_port_io.c. (CVE-2019-11811)

  - In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy
    blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user
    ID. For example, this allows bypass of !root configuration, and USER= logging, for a sudo -u
    \#$((0xffffffff)) command. (CVE-2019-14287)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to
    Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2019-2945)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Kerberos). Supported
    versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via Kerberos to compromise Java
    SE, Java SE Embedded. While the vulnerability is in Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2949)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: 2D). Supported
    versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2962)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Concurrency).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component
    without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web
    service. (CVE-2019-2964)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JAXP). Supported
    versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2973, CVE-2019-2981)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Scripting). Supported
    versions that are affected are Java SE: 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data and unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2975)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2978)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2983)

  - Vulnerability in the Java SE product of Oracle Java SE (component: 2D). Supported versions that are
    affected are Java SE: 11.0.4 and 13. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise Java SE. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a partial denial of service (partial DOS) of Java SE. Note:
    This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2019-2987)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: 2D). Supported
    versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to
    Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an
    administrator). (CVE-2019-2988, CVE-2019-2992)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u231, 8u221, 11.0.4 and 13; Java SE Embedded: 8u221.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. While the vulnerability is in Java SE, Java SE
    Embedded, attacks may significantly impact additional products. Successful attacks of this vulnerability
    can result in unauthorized creation, deletion or modification access to critical data or all Java SE, Java
    SE Embedded accessible data. Note: This vulnerability applies to Java deployments, typically in clients
    running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the specified Component, e.g., through a web service
    which supplies data to the APIs. (CVE-2019-2989)

  - Vulnerability in the Java SE product of Oracle Java SE (component: Javadoc). Supported versions that are
    affected are Java SE: 7u231, 8u221, 11.0.4 and 13. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Java SE. Successful
    attacks require human interaction from a person other than the attacker and while the vulnerability is in
    Java SE, attacks may significantly impact additional products. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete access to some of Java SE accessible data as well as
    unauthorized read access to a subset of Java SE accessible data. Note: This vulnerability applies to Java
    deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets
    (in Java SE 8), that load and run untrusted code (e.g., code that comes from the internet) and rely on the
    Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code installed by an administrator). (CVE-2019-2999)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.10.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?020232b4");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14287");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.10.10', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.10.10 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '5.10.10', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.10.10 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
