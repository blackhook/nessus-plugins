#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:2169. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127690);
  script_version("1.5");
  script_cvs_date("Date: 2020/01/06");

  script_cve_id("CVE-2018-5383");
  script_xref(name:"RHSA", value:"2019:2169");

  script_name(english:"RHEL 7 : linux-firmware (RHSA-2019:2169)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3395ff0b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2019:2169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-5383"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl100-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl1000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl105-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl135-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl2000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl2030-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl3160-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl3945-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl4965-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl5000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl5150-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl6000-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl6000g2a-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl6000g2b-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl6050-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl7260-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:iwl7265-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:linux-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2019:2169";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", reference:"iwl100-firmware-39.31.5.1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl1000-firmware-39.31.5.1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl105-firmware-18.168.6.1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl135-firmware-18.168.6.1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl2000-firmware-18.168.6.1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl2030-firmware-18.168.6.1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl3160-firmware-22.0.7.0-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl3945-firmware-15.32.2.9-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl4965-firmware-228.61.2.24-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl5000-firmware-8.83.5.1_1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl5150-firmware-8.24.2.2-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl6000-firmware-9.221.4.1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl6000g2a-firmware-17.168.5.3-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl6000g2b-firmware-17.168.5.2-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl6050-firmware-41.28.5.1-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl7260-firmware-22.0.7.0-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"iwl7265-firmware-22.0.7.0-72.el7")) flag++;
  if (rpm_check(release:"RHEL7", reference:"linux-firmware-20190429-72.gitddde598.el7")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "iwl100-firmware / iwl1000-firmware / iwl105-firmware / etc");
  }
}
