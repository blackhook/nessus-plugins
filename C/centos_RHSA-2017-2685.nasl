#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2685 and 
# CentOS Errata and Security Advisory 2017:2685 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103145);
  script_version("3.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000250");
  script_xref(name:"RHSA", value:"2017:2685");

  script_name(english:"CentOS 6 / 7 : bluez (CESA-2017:2685) (BlueBorne)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # https://lists.centos.org/pipermail/centos-announce/2017-September/022531.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db53dd90"
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-September/022535.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c08d2132"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bluez packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000250");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-hid2hci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bluez-libs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/13");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x / 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"bluez-4.66-2.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bluez-alsa-4.66-2.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bluez-compat-4.66-2.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bluez-cups-4.66-2.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bluez-gstreamer-4.66-2.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bluez-libs-4.66-2.el6_9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bluez-libs-devel-4.66-2.el6_9")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bluez-5.44-4.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bluez-cups-5.44-4.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bluez-hid2hci-5.44-4.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bluez-libs-5.44-4.el7_4")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"bluez-libs-devel-5.44-4.el7_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bluez / bluez-alsa / bluez-compat / bluez-cups / bluez-gstreamer / etc");
}
