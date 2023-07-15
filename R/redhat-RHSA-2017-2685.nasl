#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2685. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103172);
  script_version("3.12");
  script_cvs_date("Date: 2019/10/24 15:35:43");

  script_cve_id("CVE-2017-1000250");
  script_xref(name:"RHSA", value:"2017:2685");

  script_name(english:"RHEL 6 / 7 : bluez (RHSA-2017:2685) (BlueBorne)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for bluez is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The bluez packages contain the following utilities for use in
Bluetooth applications: hcitool, hciattach, hciconfig, bluetoothd,
l2ping, start scripts (Red Hat), and pcmcia configuration files.

Security Fix(es) :

* An information-disclosure flaw was found in the bluetoothd
implementation of the Service Discovery Protocol (SDP). A specially
crafted Bluetooth device could, without prior pairing or user
interaction, retrieve portions of the bluetoothd process memory,
including potentially sensitive information such as Bluetooth
encryption keys. (CVE-2017-1000250)

Red Hat would like to thank Armis Labs for reporting this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/errata/RHSA-2017:2685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2017-1000250"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-hid2hci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:2685";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"bluez-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bluez-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"bluez-alsa-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bluez-alsa-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"bluez-compat-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bluez-compat-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"bluez-cups-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bluez-cups-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"bluez-debuginfo-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bluez-debuginfo-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"bluez-gstreamer-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bluez-gstreamer-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"bluez-libs-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bluez-libs-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"bluez-libs-devel-4.66-2.el6_9")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"bluez-libs-devel-4.66-2.el6_9")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"bluez-5.44-4.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"bluez-5.44-4.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"bluez-cups-5.44-4.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"bluez-cups-5.44-4.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"bluez-debuginfo-5.44-4.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"bluez-hid2hci-5.44-4.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"bluez-hid2hci-5.44-4.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"bluez-libs-5.44-4.el7_4")) flag++;

  if (rpm_check(release:"RHEL7", reference:"bluez-libs-devel-5.44-4.el7_4")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez / bluez-alsa / bluez-compat / bluez-cups / bluez-debuginfo / etc");
  }
}
