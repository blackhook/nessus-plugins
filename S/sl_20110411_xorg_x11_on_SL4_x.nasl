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
  script_id(61015);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-0465");
  script_xref(name:"IAVA", value:"2017-A-0098");

  script_name(english:"Scientific Linux Security Update : xorg-x11 on SL4.x i386/x86_64");
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
"A flaw was found in the X.Org X server resource database utility,
xrdb. Certain variables were not properly sanitized during the launch
of a user's graphical session, which could possibly allow a remote
attacker to execute arbitrary code with root privileges, if they were
able to make the display manager execute xrdb with a specially crafted
X client hostname. For example, by configuring the hostname on the
target system via a crafted DHCP reply, or by using the X Display
Manager Control Protocol (XDMCP) to connect to that system from a host
that has a special DNS name. (CVE-2011-0465)

All running X.Org server instances must be restarted for this update
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=1462
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1ba9dfc8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"xorg-x11-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Mesa-libGL-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Mesa-libGLU-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Xdmx-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Xnest-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-Xvfb-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-deprecated-libs-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-deprecated-libs-devel-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-devel-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-doc-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-font-utils-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-libs-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-sdk-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-tools-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-twm-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-xauth-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-xdm-6.8.2-1.EL.67")) flag++;
if (rpm_check(release:"SL4", reference:"xorg-x11-xfs-6.8.2-1.EL.67")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
