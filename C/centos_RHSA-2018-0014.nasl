#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:0014 and 
# CentOS Errata and Security Advisory 2018:0014 respectively.
#

include("compat.inc");

if (description)
{
  script_id(105591);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/15");

  script_cve_id("CVE-2017-5715");
  script_xref(name:"RHSA", value:"2018:0014");
  script_xref(name:"IAVA", value:"2018-A-0020");

  script_name(english:"CentOS 7 : linux-firmware (CESA-2018:0014) (Spectre)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"An update for linux-firmware is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The linux-firmware packages contain all of the firmware files that are
required by various devices to operate.

Security Fix(es) :

* An industry-wide issue was found in the way many modern
microprocessor designs have implemented speculative execution of
instructions (a commonly used performance optimization). There are
three primary variants of the issue which differ in the way the
speculative execution can be exploited. Variant CVE-2017-5715 triggers
the speculative execution by utilizing branch target injection. It
relies on the presence of a precisely-defined instruction sequence in
the privileged code as well as the fact that memory accesses may cause
allocation into the microprocessor's data cache even for speculatively
executed instructions that never actually commit (retire). As a
result, an unprivileged attacker could use this flaw to cross the
syscall and guest/host boundaries and read privileged memory by
conducting targeted cache side-channel attacks. (CVE-2017-5715)

Note: This is the microcode counterpart of the CVE-2017-5715 kernel
mitigation.

Red Hat would like to thank Google Project Zero for reporting this
issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2018-January/022698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dbf629d6"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected linux-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5715");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:iwl7265-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/05");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl100-firmware-39.31.5.1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl1000-firmware-39.31.5.1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl105-firmware-18.168.6.1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl135-firmware-18.168.6.1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl2000-firmware-18.168.6.1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl2030-firmware-18.168.6.1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl3160-firmware-22.0.7.0-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl3945-firmware-15.32.2.9-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl4965-firmware-228.61.2.24-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl5000-firmware-8.83.5.1_1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl5150-firmware-8.24.2.2-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl6000-firmware-9.221.4.1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl6000g2a-firmware-17.168.5.3-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl6000g2b-firmware-17.168.5.2-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl6050-firmware-41.28.5.1-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl7260-firmware-22.0.7.0-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl7265-firmware-22.0.7.0-57.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"linux-firmware-20170606-57.gitc990aae.el7")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc");
}
