#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1540 and 
# CentOS Errata and Security Advisory 2013:1540 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79158);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2013-4166");
  script_xref(name:"RHSA", value:"2013:1540");

  script_name(english:"CentOS 6 : cheese / control-center / ekiga / evolution / evolution-data-server / etcgnome-panel / etc (CESA-2013:1540)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix one security issue, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Evolution is the integrated collection of email, calendaring, contact
management, communications, and personal information management (PIM)
tools for the GNOME desktop environment.

A flaw was found in the way Evolution selected GnuPG public keys when
encrypting emails. This could result in emails being encrypted with
public keys other than the one belonging to the intended recipient.
(CVE-2013-4166)

The Evolution packages have been upgraded to upstream version 2.32.3,
which provides a number of bug fixes and enhancements over the
previous version. These changes include implementation of Gnome XDG
Config Folders, and support for Exchange Web Services (EWS) protocol
to connect to Microsoft Exchange servers. EWS support has been added
as a part of the evolution-exchange packages. (BZ#883010, BZ#883014,
BZ#883015, BZ#883017, BZ#524917, BZ#524921, BZ#883044)

The gtkhtml3 packages have been upgraded to upstream version 2.32.2,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#883019)

The libgdata packages have been upgraded to upstream version 0.6.4,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#883032)

This update also fixes the following bug :

* The Exchange Calendar could not fetch the 'Free' and 'Busy'
information for meeting attendees when using Microsoft Exchange 2010
servers, and this information thus could not be displayed. This
happened because Microsoft Exchange 2010 servers use more strict rules
for 'Free' and 'Busy' information fetching. With this update, the
respective code in the openchange packages has been modified so the
'Free' and 'Busy' information fetching now complies with the fetching
rules on Microsoft Exchange 2010 servers. The 'Free' and 'Busy'
information can now be displayed as expected in the Exchange Calendar.
(BZ#665967)

All Evolution users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements. All running instances of Evolution must be restarted for
this update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000906.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5376bcde"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000912.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcef7254"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000927.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e8fd36c4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000929.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?791f1908"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000930.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f538e405"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000931.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?029f7e7f"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000932.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3ec8ef9"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb6da0d2"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e22e3fd6"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?852a71c4"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/000982.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89acb39a"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/001015.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2aa25702"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/001027.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?932b1b12"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/001047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c72417d1"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/001050.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?001dc88c"
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2013-November/001100.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3aba120"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-4166");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cheese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:control-center-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:control-center-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ekiga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-data-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-exchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-mapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-panel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-panel-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-brasero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-bugbuddy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-gnomedesktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-gnomekeyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-gnomeprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-gtksourceview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-libgtop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-libwnck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-metacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-python2-totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtkhtml3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtkhtml3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgdata-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-sendto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nautilus-sendto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openchange-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openchange-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openchange-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:planner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:planner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:planner-eds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-jamendo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-mozplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-upnp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:totem-youtube");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"cheese-2.28.1-8.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"control-center-2.28.1-39.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"control-center-devel-2.28.1-39.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"control-center-extra-2.28.1-39.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"control-center-filesystem-2.28.1-39.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ekiga-3.2.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-2.32.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-data-server-2.32.3-18.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-data-server-devel-2.32.3-18.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-data-server-doc-2.32.3-18.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-devel-2.32.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-devel-docs-2.32.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-exchange-2.32.3-16.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-help-2.32.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-mapi-0.32.2-12.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-mapi-devel-0.32.2-12.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-perl-2.32.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-pst-2.32.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"evolution-spamassassin-2.32.3-30.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"finch-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"finch-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-panel-2.30.2-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-panel-devel-2.30.2-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-panel-libs-2.30.2-15.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-applet-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-brasero-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-bugbuddy-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-desktop-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-evince-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-evolution-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-gnomedesktop-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-gnomekeyring-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-gnomeprint-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-gtksourceview-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-libgtop2-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-libwnck-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-metacity-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-rsvg-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gnome-python2-totem-2.28.0-5.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gtkhtml3-3.32.2-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gtkhtml3-devel-3.32.2-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libgdata-0.6.4-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libgdata-devel-0.6.4-2.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-perl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libpurple-tcl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nautilus-sendto-2.28.2-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nautilus-sendto-devel-2.28.2-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openchange-1.0-6.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openchange-client-1.0-6.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openchange-devel-1.0-6.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openchange-devel-docs-1.0-6.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-docs-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pidgin-perl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"planner-0.14.4-10.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"planner-devel-0.14.4-10.el6")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"planner-eds-0.14.4-10.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"totem-2.28.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"totem-devel-2.28.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"totem-jamendo-2.28.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"totem-mozplugin-2.28.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"totem-nautilus-2.28.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"totem-upnp-2.28.6-4.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"totem-youtube-2.28.6-4.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cheese / control-center / control-center-devel / etc");
}
