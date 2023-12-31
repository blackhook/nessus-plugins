#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0135 and 
# CentOS Errata and Security Advisory 2013:0135 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(63580);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2012-2370");
  script_bugtraq_id(53548);
  script_xref(name:"RHSA", value:"2013:0135");

  script_name(english:"CentOS 5 : gtk2 (CESA-2013:0135)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gtk2 packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

GIMP Toolkit (GTK+) is a multi-platform toolkit for creating graphical
user interfaces.

An integer overflow flaw was found in the X BitMap (XBM) image file
loader in GTK+. A remote attacker could provide a specially crafted
XBM image file that, when opened in an application linked against GTK+
(such as Nautilus), would cause the application to crash.
(CVE-2012-2370)

This update also fixes the following bugs :

* Due to a bug in the Input Method GTK+ module, the usage of the
Taiwanese Big5 (zh_TW.Big-5) locale led to the unexpected termination
of certain applications, such as the GDM greeter. The bug has been
fixed, and the Taiwanese locale no longer causes applications to
terminate unexpectedly. (BZ#487630)

* When a file was initially selected after the GTK+ file chooser
dialog was opened and the Location field was visible, pressing the
Enter key did not open the file. With this update, the initially
selected file is opened regardless of the visibility of the Location
field. (BZ#518483)

* When a file was initially selected after the GTK+ file chooser
dialog was opened and the Location field was visible, pressing the
Enter key did not change into the directory. With this update, the
dialog changes into the initially selected directory regardless of the
visibility of the Location field. (BZ#523657)

* Previously, the GTK Print dialog did not reflect the user-defined
printer preferences stored in the ~/.cups/lpoptions file, such as
those set in the Default Printer preferences panel. Consequently, the
first device in the printer list was always set as a default printer.
With this update, the underlying source code has been enhanced to
parse the option file. As a result, the default values in the print
dialog are set to those previously specified by the user. (BZ#603809)

* The GTK+ file chooser did not properly handle saving of nameless
files. Consequently, attempting to save a file without specifying a
file name caused GTK+ to become unresponsive. With this update, an
explicit test for this condition has been added into the underlying
source code. As a result, GTK+ no longer hangs in the described
scenario. (BZ#702342)

* When using certain graphics tablets, the GTK+ library incorrectly
translated the input coordinates. Consequently, an offset occurred
between the position of the pen and the content drawn on the screen.
This issue was limited to the following configuration: a Wacom tablet
with input coordinates bound to a single monitor in a dual head
configuration, drawing with a pen with the pressure sensitivity option
enabled. With this update, the coordinate translation method has been
changed, and the offset is no longer present in the described
configuration. (BZ#743658)

* Previously, performing drag and drop operations on tabs in
applications using the GtkNotebook widget could lead to releasing the
same resource twice. Eventually, this behavior caused the applications
to terminate with a segmentation fault. This bug has been fixed, and
the applications using GtkNotebook no longer terminate in the
aforementioned scenario. (BZ#830901)

All users of GTK+ are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2013-January/019150.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?917b1fd7"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-January/000352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b5003cf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gtk2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2370");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"gtk2-2.10.4-29.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"gtk2-devel-2.10.4-29.el5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk2 / gtk2-devel");
}
