#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0286.
#

include("compat.inc");

if (description)
{
  script_id(119566);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/28");

  script_cve_id("CVE-2017-17805", "CVE-2017-17806", "CVE-2018-10902", "CVE-2018-13094", "CVE-2018-18690", "CVE-2018-7755");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2018-0286)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - xfs: don't call xfs_da_shrink_inode with NULL bp (Eric
    Sandeen) [Orabug: 28898616] (CVE-2018-13094)

  - ALSA: rawmidi: Change resized buffers atomically
    (Takashi Iwai) [Orabug: 28898636] (CVE-2018-10902)

  - md/raid5: fix a race condition in stripe batch (Shaohua
    Li) [Orabug: 28917012]

  - xfs: don't fail when converting shortform attr to long
    form during ATTR_REPLACE (Darrick J. Wong) [Orabug:
    28924091] (CVE-2018-18690)

  - certs: Add Oracle's new X509 cert into the kernel
    keyring (Eric Snowberg) [Orabug: 28926203]

  - block: fix bdi vs gendisk lifetime mismatch (Shan Hai)
    [Orabug: 28945039]

  - Add the following entries to
    'uek-rpm/ol[67]/nano_modules.list':
    kernel/drivers/net/net_failover.ko
    kernel/net/core/failover.ko Fixes: b3bc7c163fc9 ('net:
    Introduce generic failover module') (Vijay Balakrishna)
    [Orabug: 28953351]

  - floppy: Do not copy a kernel pointer to user memory in
    FDGETPRM ioctl (Andy Whitcroft) [Orabug: 28956547]
    (CVE-2018-7755) (CVE-2018-7755)

  - iov_iter: don't revert iov buffer if csum error (Ding
    Tianhong) [Orabug: 28960296]

  - crypto: salsa20 - fix blkcipher_walk API usage (Eric
    Biggers) [Orabug: 28976583] (CVE-2017-17805)

  - crypto: hmac - require that the underlying hash
    algorithm is unkeyed (Eric Biggers) [Orabug: 28976653]
    (CVE-2017-17806)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-December/000921.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9322ac99"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.23.1.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.23.1.el6uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
