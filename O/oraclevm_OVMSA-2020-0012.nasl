#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0012.
#

include("compat.inc");

if (description)
{
  script_id(135572);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2020-5208");

  script_name(english:"OracleVM 3.3 : ipmitool (OVMSA-2020-0012)");
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

  - Backport fix for (CVE-2020-5208)

  - Fix missing return in ipmi_kontronoem_main - CID#1261317

  - rebase to latest stable upstream version

  - resolves: rhbz#1253416

  - remove the redundant OpenIMPI dependency

  - resolves: rhbz#1262111

  - (#1085072) Correct init paths.

  - (#878614) SDR long sensor names.

  - (#1194420) Fix DDR4 SDR crash.

  - (#1170266) Wrong version reported.

  - (#1162175) Extra dependency.

  - (#1126333) Very slow response from SDR owner type SW ID

  - (#903019) SDR lists x4600m2 fan units as unspecified

  - (#1028163) Fix environment variable parsing.

  - (#1056581) IPv6 connectivity support.

  - (#1029529) Fix dependency for kernel module loading.

  - (#923192) ipmi command retry no longer shifts replies

  - (#903251) - link=on and ipmi=on no longer work for
    setaccess

  - fixed retransmissions of lanplus requests, broken in
    previous release (#826027)

  - added new options to configure retransmissions on
    lan/lanplus interfaces (#748073)

  - updated dellem command (#739358)

  - fixed exit code of ipmitool -o list (#715615)

  - improved checking of command line arguments (#725993)

  - fixed wrong permissions on ipmievd.pid (#756685)

  - fixed delloem powermonitor on bigendian systems
    (#731718)

  - fixed memory leak in Serial-over-Lan module (#731977)

  - added -Y option for ipmitool to hide Kg key from cmdline
    (#698647)

  - added 'channel setkg' command to set Kg encryption key
    on remote machine (#726390)

  - updated 'delloem setled' command to indicate SES status
    and drive activities for a PCI-e SSD (#727314)

  - rebuilt for RHEL 6.2 Fastrack

  - fixed 'ipmi sol' sending wrong packets due to
    miscalculation of SOL payload size (#675975)

  - added 'delloem' command for Dell-specific IPMI
    extensions (#631649, #63793)

  - Changed ipmievd to use /var/run/ipmievd.pid file by
    default (#596809)

  - Fixed exit code of ipmievd initscript with wrong
    arguments (#562186)

  - Rebuilt for RHEL 6

  - fix ipmievd initscript 'condrestart' action (#532188)

  - rebuilt with new openssl

  - Rebuilt for

  - updated to new version

  - Rebuilt for

  - rebuild with new openssl

  - fix issues found during package review :

  - clear Default-Start: line in the init script, the
    service should be disabled by default

  - added Obsoletes: OpenIPMI-tools

  - compile with --disable-dependency-tracking to speed
    things up

  - compile with --enable-file-security

  - compile with --disable-intf-free, don't depend on
    FreeIPMI libraries (FreeIPMI has its own ipmitool-like
    utility)

  - package created, based on upstream .spec file"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-April/000976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61a6a978"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected ipmitool package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:ipmitool");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.3", reference:"ipmitool-1.8.15-3.el6_10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipmitool");
}
