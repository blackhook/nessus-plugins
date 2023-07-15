#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71298);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-4166");

  script_name(english:"Scientific Linux Security Update : evolution on SL6.x i386/x86_64 (20131121)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way Evolution selected GnuPG public keys when
encrypting emails. This could result in emails being encrypted with
public keys other than the one belonging to the intended recipient.
(CVE-2013-4166)

The Evolution packages have been upgraded to upstream version 2.32.3,
which provides a number of bug fixes and enhancements over the
previous version. These changes include implementation of Gnome XDG
Config Folders, and support for Exchange Web Services (EWS) protocol
to connect to Microsoft Exchange servers. EWS support has been added
as a part of the evolution-exchange packages.

The gtkhtml3 packages have been upgraded to upstream version 2.32.2,
which provides a number of bug fixes and enhancements over the
previous version.

The libgdata packages have been upgraded to upstream version 0.6.4,
which provides a number of bug fixes and enhancements over the
previous version.

This update also fixes the following bug :

  - The Exchange Calendar could not fetch the 'Free' and
    'Busy' information for meeting attendees when using
    Microsoft Exchange 2010 servers, and this information
    thus could not be displayed. This happened because
    Microsoft Exchange 2010 servers use more strict rules
    for 'Free' and 'Busy' information fetching. With this
    update, the respective code in the openchange packages
    has been modified so the 'Free' and 'Busy' information
    fetching now complies with the fetching rules on
    Microsoft Exchange 2010 servers. The 'Free' and 'Busy'
    information can now be displayed as expected in the
    Exchange Calendar.

All running instances of Evolution must be restarted for this update
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=2188
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15906620"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cheese");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:cheese-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:control-center");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:control-center-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:control-center-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:control-center-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:control-center-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ekiga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ekiga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-data-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-exchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-exchange-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-help");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-mapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-mapi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-mapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-pst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:evolution-spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-panel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-panel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-panel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-panel-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-brasero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-bugbuddy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-gnomedesktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-gnomekeyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-gnomeprint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-gtksourceview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-libgtop2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-libwnck");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-metacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnome-python2-totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtkhtml3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtkhtml3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gtkhtml3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgdata-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libgdata-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nautilus-sendto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nautilus-sendto-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:nautilus-sendto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openchange-devel-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:planner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:planner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:planner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:planner-eds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:totem-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:totem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:totem-jamendo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:totem-mozplugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:totem-nautilus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:totem-upnp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:totem-youtube");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"cheese-2.28.1-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"cheese-debuginfo-2.28.1-8.el6")) flag++;
if (rpm_check(release:"SL6", reference:"control-center-2.28.1-39.el6")) flag++;
if (rpm_check(release:"SL6", reference:"control-center-debuginfo-2.28.1-39.el6")) flag++;
if (rpm_check(release:"SL6", reference:"control-center-devel-2.28.1-39.el6")) flag++;
if (rpm_check(release:"SL6", reference:"control-center-extra-2.28.1-39.el6")) flag++;
if (rpm_check(release:"SL6", reference:"control-center-filesystem-2.28.1-39.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ekiga-3.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"ekiga-debuginfo-3.2.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-2.32.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-data-server-2.32.3-18.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-data-server-debuginfo-2.32.3-18.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-data-server-devel-2.32.3-18.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-data-server-doc-2.32.3-18.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-debuginfo-2.32.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-devel-2.32.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-devel-docs-2.32.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-exchange-2.32.3-16.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-exchange-debuginfo-2.32.3-16.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-help-2.32.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-mapi-0.32.2-12.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-mapi-debuginfo-0.32.2-12.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-mapi-devel-0.32.2-12.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-perl-2.32.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-pst-2.32.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"evolution-spamassassin-2.32.3-30.el6")) flag++;
if (rpm_check(release:"SL6", reference:"finch-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"finch-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-panel-2.30.2-15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-panel-debuginfo-2.30.2-15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-panel-devel-2.30.2-15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-panel-libs-2.30.2-15.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-applet-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-brasero-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-bugbuddy-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-desktop-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-desktop-debuginfo-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-evince-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-evolution-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-gnomedesktop-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-gnomekeyring-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-gnomeprint-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-gtksourceview-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-libgtop2-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-libwnck-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-metacity-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-rsvg-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gnome-python2-totem-2.28.0-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gtkhtml3-3.32.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gtkhtml3-debuginfo-3.32.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"gtkhtml3-devel-3.32.2-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libgdata-0.6.4-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libgdata-debuginfo-0.6.4-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libgdata-devel-0.6.4-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-perl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libpurple-tcl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nautilus-sendto-2.28.2-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nautilus-sendto-debuginfo-2.28.2-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nautilus-sendto-devel-2.28.2-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-1.0-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-client-1.0-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-debuginfo-1.0-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-devel-1.0-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"openchange-devel-docs-1.0-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-debuginfo-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-devel-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-docs-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pidgin-perl-2.7.9-11.el6")) flag++;
if (rpm_check(release:"SL6", reference:"planner-0.14.4-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"planner-debuginfo-0.14.4-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"planner-devel-0.14.4-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"planner-eds-0.14.4-10.el6")) flag++;
if (rpm_check(release:"SL6", reference:"totem-2.28.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"totem-debuginfo-2.28.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"totem-devel-2.28.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"totem-jamendo-2.28.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"totem-mozplugin-2.28.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"totem-nautilus-2.28.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"totem-upnp-2.28.6-4.el6")) flag++;
if (rpm_check(release:"SL6", reference:"totem-youtube-2.28.6-4.el6")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cheese / cheese-debuginfo / control-center / etc");
}
