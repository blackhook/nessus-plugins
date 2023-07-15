#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164592);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2021-2161",
    "CVE-2021-2163",
    "CVE-2021-20305",
    "CVE-2021-25215",
    "CVE-2021-26937",
    "CVE-2021-27363",
    "CVE-2021-27364",
    "CVE-2021-27365"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.20.1)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.20.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.20.1 advisory.

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

  - encoding.c in GNU Screen through 4.8.0 allows remote attackers to cause a denial of service (invalid write
    access and application crash) or possibly have unspecified other impact via a crafted UTF-8 character
    sequence. (CVE-2021-26937)

  - An issue was discovered in the Linux kernel through 5.11.3. A kernel pointer leak can be used to determine
    the address of the iscsi_transport structure. When an iSCSI transport is registered with the iSCSI
    subsystem, the transport's handle is available to unprivileged users via the sysfs file system, at
    /sys/class/iscsi_transport/$TRANSPORT_NAME/handle. When read, the show_transport_handle function (in
    drivers/scsi/scsi_transport_iscsi.c) is called, which leaks the handle. This handle is actually the
    pointer to an iscsi_transport struct in the kernel module's global variables. (CVE-2021-27363)

  - An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged user to craft Netlink messages. (CVE-2021-27364)

  - An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a
    Netlink message. (CVE-2021-27365)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.20.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70aa8a1e");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26937");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
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
  { 'fixed_version' : '5.20.1', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.20.1 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '5.20.1', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.20.1 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
