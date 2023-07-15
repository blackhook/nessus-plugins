#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0013.
#

include("compat.inc");

if (description)
{
  script_id(106243);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"OracleVM 3.4 : microcode_ctl (OVMSA-2018-0013) (Spectre)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Revert: early microcode load to allow updating Broadwell
    model 79

  - Revert: Make sure 'modprobe microcode' is not executed
    on Broadwell model 79

  - Revert: Run dracut upon microcode update

  - Revert updated Intel 20180108 microcode for CPUIDs:
    (CVE-2017-5715) 306c3 (06-3c-03 rev 0x23, Haswell) 
    306d4 (06-3d-04 rev 0x28, Broadwell)  306f2 (06-3f-02
    rev 0x3b, Haswell)  306f4 (06-3f-04 rev 0x10, Haswell) 
    306e4 (06-3e-04 rev 0x42a, Ivy Bridge)  40651 (06-45-01
    rev 0x21, Haswell)  40661 (06-46-01 rev 0x18, Haswell) 
    40671 (06-47-01 rev 0x1b, Broadwell)  406e3 (06-4e-03
    rev 0xc2, Skylake)  406f1 (06-4f-01 rev 0xb000025,
    Broadwell)  50654 (06-55-04 rev 0x200003c, Skylake) 
    50662 (06-56-02 rev 0x14, Broadwell)  50663 (06-56-03
    rev 0x7000011, Broadwell)  506e3 (06-5e-03 rev 0xc2,
    Skylake)  706a1 (06-7a-01 rev 0x22)  806e9 (06-8e-09 rev
    0x80, Kaby Lake)  806ea (06-8e-0a rev 0x80)  906e9
    (06-9e-09 rev 0x80, Kaby Lake) 906ea (06-9e-0a rev
    0x80)  906eb (06-9e-0b rev 0x80)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-January/000823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24b9afdb"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected microcode_ctl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:microcode_ctl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/23");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.4", reference:"microcode_ctl-1.17-25.4.0.2.el6_9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "microcode_ctl");
}
