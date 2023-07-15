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
  script_id(79230);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-6051", "CVE-2014-6052", "CVE-2014-6053", "CVE-2014-6054", "CVE-2014-6055");

  script_name(english:"Scientific Linux Security Update : libvncserver on SL6.x, SL7.x i386/x86_64 (20141111)");
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
"An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way screen sizes were handled by LibVNCServer. A
malicious VNC server could use this flaw to cause a client to crash
or, potentially, execute arbitrary code in the client. (CVE-2014-6051)

A NULL pointer dereference flaw was found in LibVNCServer's
framebuffer setup. A malicious VNC server could use this flaw to cause
a VNC client to crash. (CVE-2014-6052)

A NULL pointer dereference flaw was found in the way LibVNCServer
handled certain ClientCutText message. A remote attacker could use
this flaw to crash the VNC server by sending a specially crafted
ClientCutText message from a VNC client. (CVE-2014-6053)

A divide-by-zero flaw was found in the way LibVNCServer handled the
scaling factor when it was set to '0'. A remote attacker could use
this flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6054)

Two stack-based buffer overflow flaws were found in the way
LibVNCServer handled file transfers. A remote attacker could use this
flaw to crash the VNC server using a malicious VNC client.
(CVE-2014-6055)

All running applications linked against libvncserver must be restarted
for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=2805
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4aeac59"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libvncserver, libvncserver-debuginfo and / or
libvncserver-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvncserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvncserver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libvncserver-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"libvncserver-0.9.7-7.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvncserver-debuginfo-0.9.7-7.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"libvncserver-devel-0.9.7-7.el6_6.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvncserver-0.9.9-9.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvncserver-debuginfo-0.9.9-9.el7_0.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libvncserver-devel-0.9.9-9.el7_0.1")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvncserver / libvncserver-debuginfo / libvncserver-devel");
}
