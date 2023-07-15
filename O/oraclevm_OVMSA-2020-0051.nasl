#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0051.
#

include("compat.inc");

if (description)
{
  script_id(142943);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/25");

  script_cve_id("CVE-2016-7913", "CVE-2016-7917", "CVE-2020-25643", "CVE-2020-8694", "CVE-2020-8695");

  script_name(english:"OracleVM 3.4 : Unbreakable / etc (OVMSA-2020-0051)");
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

  - powercap: restrict energy meter to root access (Kanth
    Ghatraju) [Orabug: 32137965] (CVE-2020-8694)
    (CVE-2020-8695)

  - Revert 'x86/efi: Initialize and display UEFI secure boot
    state a bit later during init' (Eric Snowberg) [Orabug:
    31887248]

  - xfs: fix xfs_inode use after free (Wengang Wang)
    [Orabug: 31932452]

  - SUNRPC: ECONNREFUSED should cause a rebind. (NeilBrown)
    [Orabug: 32070175]

  - netfilter: nfnetlink: correctly validate length of batch
    messages (Phil Turnbull) [Orabug: 30658635]
    (CVE-2016-7917)

  - xc2028: Fix use-after-free bug properly (Takashi Iwai)
    [Orabug: 30658659] (CVE-2016-7913)

  - [media] xc2028: avoid use after free (Mauro Carvalho
    Chehab) [Orabug: 30658659] (CVE-2016-7913)

  - uek-rpm: Create initramfs at postinstall stage also.
    (Somasundaram Krishnasamy) [Orabug: 30821411]

  - hdlc_ppp: add range checks in ppp_cp_parse_cr (Dan
    Carpenter) [Orabug: 31989190] (CVE-2020-25643)

  - tracing: Reverse the order of trace_types_lock and
    event_mutex (Alan Maguire) [Orabug: 32002706]

  - ocfs2/dlm: move lock to the tail of grant queue while
    doing in-place convert (xuejiufei) [Orabug: 32071234]"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-November/001004.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e9791fe"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7913");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-4.1.12-124.45.2.el6uek")) flag++;
if (rpm_check(release:"OVS3.4", reference:"kernel-uek-firmware-4.1.12-124.45.2.el6uek")) flag++;

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
