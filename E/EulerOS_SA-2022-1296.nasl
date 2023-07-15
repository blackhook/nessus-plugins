#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158523);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id(
    "CVE-2018-18440",
    "CVE-2019-11059",
    "CVE-2019-11690",
    "CVE-2019-13103",
    "CVE-2019-13104",
    "CVE-2019-13106",
    "CVE-2019-14192",
    "CVE-2019-14193",
    "CVE-2019-14194",
    "CVE-2019-14195",
    "CVE-2019-14196",
    "CVE-2019-14197",
    "CVE-2019-14198",
    "CVE-2019-14199",
    "CVE-2019-14200",
    "CVE-2019-14201",
    "CVE-2019-14202",
    "CVE-2019-14203",
    "CVE-2019-14204"
  );

  script_name(english:"EulerOS 2.0 SP9 : uboot-tools (EulerOS-SA-2022-1296)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the uboot-tools package installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

  - DENX U-Boot through 2018.09-rc1 has a locally exploitable buffer overflow via a crafted kernel image
    because filesystem loading is mishandled. (CVE-2018-18440)

  - Das U-Boot 2016.11-rc1 through 2019.04 mishandles the ext4 64-bit extension, resulting in a buffer
    overflow. (CVE-2019-11059)

  - gen_rand_uuid in lib/uuid.c in Das U-Boot v2014.04 through v2019.04 lacks an srand call, which allows
    attackers to determine UUID values in scenarios where CONFIG_RANDOM_UUID is enabled, and Das U-Boot is
    relied upon for UUID values of a GUID Partition Table of a boot device. (CVE-2019-11690)

  - A crafted self-referential DOS partition table will cause all Das U-Boot versions through 2019.07-rc4 to
    infinitely recurse, causing the stack to grow infinitely and eventually either crash or overwrite other
    data. (CVE-2019-13103)

  - In Das U-Boot versions 2016.11-rc1 through 2019.07-rc4, an underflow can cause memcpy() to overwrite a
    very large amount of data (including the whole stack) while reading a crafted ext4 filesystem.
    (CVE-2019-13104)

  - Das U-Boot versions 2016.09 through 2019.07-rc4 can memset() too much data while reading a crafted ext4
    filesystem, which results in a stack buffer overflow and likely code execution. (CVE-2019-13106)

  - An issue was discovered in Das U-Boot through 2019.07. There is an unbounded memcpy when parsing a UDP
    packet due to a net_process_received_packet integer underflow during an nc_input_packet call.
    (CVE-2019-14192)

  - An issue was discovered in Das U-Boot through 2019.07. There is an unbounded memcpy with an unvalidated
    length at nfs_readlink_reply, in the 'if' block after calculating the new path length. (CVE-2019-14193)

  - An issue was discovered in Das U-Boot through 2019.07. There is an unbounded memcpy with a failed length
    check at nfs_read_reply when calling store_block in the NFSv2 case. (CVE-2019-14194)

  - An issue was discovered in Das U-Boot through 2019.07. There is an unbounded memcpy with unvalidated
    length at nfs_readlink_reply in the 'else' block after calculating the new path length. (CVE-2019-14195)

  - An issue was discovered in Das U-Boot through 2019.07. There is an unbounded memcpy with a failed length
    check at nfs_lookup_reply. (CVE-2019-14196)

  - An issue was discovered in Das U-Boot through 2019.07. There is a read of out-of-bounds data at
    nfs_read_reply. (CVE-2019-14197)

  - An issue was discovered in Das U-Boot through 2019.07. There is an unbounded memcpy with a failed length
    check at nfs_read_reply when calling store_block in the NFSv3 case. (CVE-2019-14198)

  - An issue was discovered in Das U-Boot through 2019.07. There is an unbounded memcpy when parsing a UDP
    packet due to a net_process_received_packet integer underflow during an *udp_packet_handler call.
    (CVE-2019-14199)

  - An issue was discovered in Das U-Boot through 2019.07. There is a stack-based buffer overflow in this
    nfs_handler reply helper function: rpc_lookup_reply. (CVE-2019-14200)

  - An issue was discovered in Das U-Boot through 2019.07. There is a stack-based buffer overflow in this
    nfs_handler reply helper function: nfs_lookup_reply. (CVE-2019-14201)

  - An issue was discovered in Das U-Boot through 2019.07. There is a stack-based buffer overflow in this
    nfs_handler reply helper function: nfs_readlink_reply. (CVE-2019-14202)

  - An issue was discovered in Das U-Boot through 2019.07. There is a stack-based buffer overflow in this
    nfs_handler reply helper function: nfs_mount_reply. (CVE-2019-14203)

  - An issue was discovered in Das U-Boot through 2019.07. There is a stack-based buffer overflow in this
    nfs_handler reply helper function: nfs_umountall_reply. (CVE-2019-14204)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1296
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?541888dc");
  script_set_attribute(attribute:"solution", value:
"Update the affected uboot-tools packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13106");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-14204");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:uboot-tools-help");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(9)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP9", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

var flag = 0;

var pkgs = [
  "uboot-tools-help-2018.09-8.h5.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"9", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "uboot-tools");
}
