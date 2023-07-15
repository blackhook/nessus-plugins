#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164614);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2020-8648",
    "CVE-2020-12362",
    "CVE-2020-12363",
    "CVE-2020-12364",
    "CVE-2020-27170",
    "CVE-2021-2161",
    "CVE-2021-2163",
    "CVE-2021-3347",
    "CVE-2021-20305",
    "CVE-2021-25215",
    "CVE-2021-25217",
    "CVE-2021-26937",
    "CVE-2021-27219"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.0.1)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.0.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.0.1 advisory.

  - Integer overflow in the firmware for some Intel(R) Graphics Drivers for Windows * before version
    26.20.100.7212 and before Linux kernel version 5.5 may allow a privileged user to potentially enable an
    escalation of privilege via local access. (CVE-2020-12362)

  - Improper input validation in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and
    before Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of service via
    local access. (CVE-2020-12363)

  - Null pointer reference in some Intel(R) Graphics Drivers for Windows* before version 26.20.100.7212 and
    before version Linux kernel version 5.5 may allow a privileged user to potentially enable a denial of
    service via local access. (CVE-2020-12364)

  - An issue was discovered in the Linux kernel before 5.11.8. kernel/bpf/verifier.c performs undesirable out-
    of-bounds speculation on pointer arithmetic, leading to side-channel attacks that defeat Spectre
    mitigations and obtain sensitive information from kernel memory, aka CID-f232326f6966. This affects
    pointer types that do not define a ptr_limit. (CVE-2020-27170)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c. (CVE-2020-8648)

  - A flaw was found in Nettle in versions before 3.7.2, where several Nettle signature verification functions
    (GOST DSA, EDDSA & ECDSA) result in the Elliptic Curve Cryptography point (ECC) multiply function being
    called with out-of-range scalers, possibly resulting in incorrect results. This flaw allows an attacker to
    force an invalid signature, causing an assertion failure or possible validation. The highest threat to
    this vulnerability is to confidentiality, integrity, as well as system availability. (CVE-2021-20305)

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks of this
    vulnerability can result in unauthorized creation, deletion or modification access to critical data or all
    Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability
    applies to Java deployments that load and run untrusted code (e.g., code that comes from the internet) and
    rely on the Java sandbox for security. It can also be exploited by supplying untrusted data to APIs in the
    specified Component. (CVE-2021-2161)

  - Vulnerability in the Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition product of Oracle Java
    SE (component: Libraries). Supported versions that are affected are Java SE: 7u291, 8u281, 11.0.10, 16;
    Java SE Embedded: 8u281; Oracle GraalVM Enterprise Edition: 19.3.5, 20.3.1.2 and 21.0.0.2. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded, Oracle GraalVM Enterprise Edition. Successful attacks require human
    interaction from a person other than the attacker. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Java SE, Java SE Embedded,
    Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments
    that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox
    for security. (CVE-2021-2163)

  - In BIND 9.0.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11 of the BIND
    9.17 development branch, when a vulnerable version of named receives a query for a record triggering the
    flaw described above, the named process will terminate due to a failed assertion check. The vulnerability
    affects all currently maintained BIND 9 branches (9.11, 9.11-S, 9.16, 9.16-S, 9.17) as well as all other
    versions of BIND 9. (CVE-2021-25215)

  - In ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16, ISC DHCP 4.4.0 -> 4.4.2 (Other branches of ISC DHCP (i.e., releases
    in the 4.0.x series or lower and releases in the 4.3.x series) are beyond their End-of-Life (EOL) and no
    longer supported by ISC. From inspection it is clear that the defect is also present in releases from
    those series, but they have not been officially tested for the vulnerability), The outcome of encountering
    the defect while reading a lease that will trigger it varies, according to: the component being affected
    (i.e., dhclient or dhcpd) whether the package was built as a 32-bit or 64-bit binary whether the compiler
    flag -fstack-protection-strong was used when compiling In dhclient, ISC has not successfully reproduced
    the error on a 64-bit system. However, on a 32-bit system it is possible to cause dhclient to crash when
    reading an improper lease, which could cause network connectivity problems for an affected system due to
    the absence of a running DHCP client process. In dhcpd, when run in DHCPv4 or DHCPv6 mode: if the dhcpd
    server binary was built for a 32-bit architecture AND the -fstack-protection-strong flag was specified to
    the compiler, dhcpd may exit while parsing a lease file containing an objectionable lease, resulting in
    lack of service to clients. Additionally, the offending lease and the lease immediately following it in
    the lease database may be improperly deleted. if the dhcpd server binary was built for a 64-bit
    architecture OR if the -fstack-protection-strong compiler flag was NOT specified, the crash will not
    occur, but it is possible for the offending lease and the lease which immediately followed it to be
    improperly deleted. (CVE-2021-25217)

  - encoding.c in GNU Screen through 4.8.0 allows remote attackers to cause a denial of service (invalid write
    access and application crash) or possibly have unspecified other impact via a crafted UTF-8 character
    sequence. (CVE-2021-26937)

  - An issue was discovered in GNOME GLib before 2.66.6 and 2.67.x before 2.67.3. The function g_bytes_new has
    an integer overflow on 64-bit platforms due to an implicit cast from 64 bits to 32 bits. The overflow
    could potentially lead to memory corruption. (CVE-2021-27219)

  - An issue was discovered in the Linux kernel through 5.10.11. PI futexes have a kernel stack use-after-free
    during fault handling, allowing local users to execute code in the kernel, aka CID-34b1a1ce1458.
    (CVE-2021-3347)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.0.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a999ff1d");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26937");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
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
  { 'fixed_version' : '6.0.1', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.0.1 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.0.1', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.0.1 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
