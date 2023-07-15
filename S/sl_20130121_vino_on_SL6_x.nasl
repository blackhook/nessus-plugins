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
  script_id(63664);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-0904", "CVE-2011-0905", "CVE-2011-1164", "CVE-2011-1165", "CVE-2012-4429");

  script_name(english:"Scientific Linux Security Update : vino on SL6.x i386/x86_64 (20130121)");
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
"It was found that Vino transmitted all clipboard activity on the
system running Vino to all clients connected to port 5900, even those
who had not authenticated. A remote attacker who is able to access
port 5900 on a system running Vino could use this flaw to read
clipboard data without authenticating. (CVE-2012-4429)

Two out-of-bounds memory read flaws were found in the way Vino
processed client framebuffer requests in certain encodings. An
authenticated client could use these flaws to send a specially crafted
request to Vino, causing it to crash. (CVE-2011-0904, CVE-2011-0905)

In certain circumstances, the vino-preferences dialog box incorrectly
indicated that Vino was only accessible from the local network. This
could confuse a user into believing connections from external networks
are not allowed (even when they are allowed). With this update,
vino-preferences no longer displays connectivity and reachable
information. (CVE-2011-1164)

There was no warning that Universal Plug and Play (UPnP) was used to
open ports on a user's network router when the 'Configure network
automatically to accept connections' option was enabled (it is
disabled by default) in the Vino preferences. This update changes the
option's description to avoid the risk of a UPnP router configuration
change without the user's consent. (CVE-2011-1165)

The GNOME session must be restarted (log out, then log back in) for
this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=2684
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f1993d2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vino and / or vino-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:vino-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/23");
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
if (rpm_check(release:"SL6", reference:"vino-2.28.1-8.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"vino-debuginfo-2.28.1-8.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vino / vino-debuginfo");
}
