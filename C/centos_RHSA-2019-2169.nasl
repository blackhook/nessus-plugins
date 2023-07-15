#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2169 and 
# CentOS Errata and Security Advisory 2019:2169 respectively.
#

include("compat.inc");

if (description)
{
  script_id(128369);
  script_version("1.3");
  script_cvs_date("Date: 2019/12/31");

  script_cve_id("CVE-2018-5383");
  script_xref(name:"RHSA", value:"2019:2169");

  script_name(english:"CentOS 7 : linux-firmware (CESA-2019:2169)");
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

* kernel: Bluetooth implementations may not sufficiently validate
elliptic curve parameters during Diffie-Hellman key exchange
(CVE-2018-5383)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 7.7 Release Notes linked from the References section."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2019-August/005978.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64e3e419"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected linux-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5383");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl100-firmware-39.31.5.1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl1000-firmware-39.31.5.1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl105-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl135-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl2000-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl2030-firmware-18.168.6.1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl3160-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl3945-firmware-15.32.2.9-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl4965-firmware-228.61.2.24-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl5000-firmware-8.83.5.1_1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl5150-firmware-8.24.2.2-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl6000-firmware-9.221.4.1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl6000g2a-firmware-17.168.5.3-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl6000g2b-firmware-17.168.5.2-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl6050-firmware-41.28.5.1-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl7260-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"iwl7265-firmware-22.0.7.0-72.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"linux-firmware-20190429-72.gitddde598.el7")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc");
}
