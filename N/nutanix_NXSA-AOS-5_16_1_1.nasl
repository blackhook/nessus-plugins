#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164606);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2019-11599",
    "CVE-2019-13734",
    "CVE-2019-14816",
    "CVE-2019-14895",
    "CVE-2019-14898",
    "CVE-2019-14901",
    "CVE-2019-17133",
    "CVE-2019-18634",
    "CVE-2020-2583",
    "CVE-2020-2590",
    "CVE-2020-2593",
    "CVE-2020-2601",
    "CVE-2020-2604",
    "CVE-2020-2654",
    "CVE-2020-2659"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.16.1.1)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.16.1.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.16.1.1 advisory.

  - The coredump implementation in the Linux kernel before 5.0.10 does not use locking or other mechanisms to
    prevent vma layout or vma flags changes while it runs, which allows local users to obtain sensitive
    information, cause a denial of service, or possibly have unspecified other impact by triggering a race
    condition with mmget_not_zero or get_task_mm calls. This is related to fs/userfaultfd.c, mm/mmap.c,
    fs/proc/task_mmu.c, and drivers/infiniband/core/uverbs_main.c. (CVE-2019-11599)

  - Out of bounds write in SQLite in Google Chrome prior to 79.0.3945.79 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2019-13734)

  - There is heap-based buffer overflow in kernel, all versions up to, excluding 5.3, in the marvell wifi chip
    driver in Linux kernel, that allows local users to cause a denial of service(system crash) or possibly
    execute arbitrary code. (CVE-2019-14816)

  - A heap-based buffer overflow was discovered in the Linux kernel, all versions 3.x.x and 4.x.x before
    4.18.0, in Marvell WiFi chip driver. The flaw could occur when the station attempts a connection
    negotiation during the handling of the remote devices country settings. This could allow the remote device
    to cause a denial of service (system crash) or possibly execute arbitrary code. (CVE-2019-14895)

  - The fix for CVE-2019-11599, affecting the Linux kernel before 5.0.10 was not complete. A local user could
    use this flaw to obtain sensitive information, cause a denial of service, or possibly have other
    unspecified impacts by triggering a race condition with mmget_not_zero or get_task_mm calls.
    (CVE-2019-14898)

  - A heap overflow flaw was found in the Linux kernel, all versions 3.x.x and 4.x.x before 4.18.0, in Marvell
    WiFi chip driver. The vulnerability allows a remote attacker to cause a system crash, resulting in a
    denial of service, or execute arbitrary code. The highest threat with this vulnerability is with the
    availability of the system. If code execution occurs, the code will run with the permissions of root. This
    will affect both confidentiality and integrity of files on the system. (CVE-2019-14901)

  - In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a
    long SSID IE, leading to a Buffer Overflow. (CVE-2019-17133)

  - In Sudo before 1.8.26, if pwfeedback is enabled in /etc/sudoers, users can trigger a stack-based buffer
    overflow in the privileged sudo process. (pwfeedback is a default setting in Linux Mint and elementary OS;
    however, it is NOT the default for upstream and many other packages, and would exist only if enabled by an
    administrator.) The attacker needs to deliver a long string to the stdin of getln() in tgetpass.c.
    (CVE-2019-18634)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded:
    8u231. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2583)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded: 8u231.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via Kerberos to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2590)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded:
    8u231. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Java SE, Java SE Embedded accessible data as well
    as unauthorized read access to a subset of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2593)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded: 8u231.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via Kerberos to
    compromise Java SE, Java SE Embedded. While the vulnerability is in Java SE, Java SE Embedded, attacks may
    significantly impact additional products. Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access to all Java SE, Java SE Embedded accessible data.
    Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web
    Start applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code
    that comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2601)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1; Java SE Embedded:
    8u231. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    takeover of Java SE, Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or sandboxed Java applets (in Java SE 8), that load
    and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for
    security. This vulnerability can also be exploited by using APIs in the specified Component, e.g., through
    a web service which supplies data to the APIs. (CVE-2020-2604)

  - Vulnerability in the Java SE product of Oracle Java SE (component: Libraries). Supported versions that are
    affected are Java SE: 7u241, 8u231, 11.0.5 and 13.0.1. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise Java SE. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service
    (partial DOS) of Java SE. Note: This vulnerability can only be exploited by supplying data to APIs in the
    specified Component without using Untrusted Java Web Start applications or Untrusted Java applets, such as
    through a web service. (CVE-2020-2654)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Networking).
    Supported versions that are affected are Java SE: 7u241 and 8u231; Java SE Embedded: 8u231. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start
    applications or sandboxed Java applets (in Java SE 8), that load and run untrusted code (e.g., code that
    comes from the internet) and rely on the Java sandbox for security. This vulnerability can also be
    exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the
    APIs. (CVE-2020-2659)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.16.1.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb6896fc");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14901");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/29");
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
  { 'fixed_version' : '5.16.1.1', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.16.1.1 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.16.1.1', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.16.1.1 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
