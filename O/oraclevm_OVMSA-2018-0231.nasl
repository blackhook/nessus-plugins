#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0231.
#

include("compat.inc");

if (description)
{
  script_id(110581);
  script_version("1.3");
  script_cvs_date("Date: 2019/09/27 13:00:35");

  script_cve_id("CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2017-1000410", "CVE-2017-17741", "CVE-2018-1000199", "CVE-2018-10323", "CVE-2018-3665");

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2018-0231)");
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

  - x86/fpu: Make eager FPU default (Mihai Carabas) [Orabug:
    28156176] (CVE-2018-3665)

  - KVM: Fix stack-out-of-bounds read in write_mmio (Wanpeng
    Li) [Orabug: 27951287] (CVE-2017-17741) (CVE-2017-17741)

  - xfs: set format back to extents if
    xfs_bmap_extents_to_btree (Eric Sandeen) [Orabug:
    27989498] (CVE-2018-10323)

  - Bluetooth: Prevent stack info leak from the EFS element.
    (Ben Seri) [Orabug: 28030520] (CVE-2017-1000410)
    (CVE-2017-1000410)

  - ALSA: hrtimer: Fix stall by hrtimer_cancel (Takashi
    Iwai) [Orabug: 28058229] (CVE-2016-2549)

  - ALSA: timer: Harden slave timer list handling (Takashi
    Iwai) [Orabug: 28058229] (CVE-2016-2547) (CVE-2016-2548)

  - ALSA: timer: Fix double unlink of active_list (Takashi
    Iwai) [Orabug: 28058229] (CVE-2016-2545)

  - ALSA: seq: Fix missing NULL check at remove_events ioctl
    (Takashi Iwai) [Orabug: 28058229] (CVE-2016-2543)

  - ALSA: seq: Fix race at timer setup and close (Takashi
    Iwai) [Orabug: 28058229] (CVE-2016-2544)

  - ALSA: usb-audio: avoid freeing umidi object twice
    (Andrey Konovalov) [Orabug: 28058229] (CVE-2016-2384)

  - perf/hwbp: Simplify the perf-hwbp code, fix
    documentation (Linus Torvalds) [Orabug: 27947608]
    (CVE-2018-1000199)

  - Revert 'perf/hwbp: Simplify the perf-hwbp code, fix
    documentation' (Brian Maly) [Orabug: 27947608]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2018-June/000866.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.21.4.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.21.4.el6uek")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
