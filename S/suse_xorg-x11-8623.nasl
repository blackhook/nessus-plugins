#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67256);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1995", "CVE-2013-1996", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2063", "CVE-2013-2066");

  script_name(english:"SuSE 10 Security Update : xorg-x11 (ZYPP Patch Number 8623)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of xorg-x11 fixes several security vulnerabilities.

  - Bug 815451- X.Org Security Advisory: May 23, 2013

  - Bug 821664 - libX11

  - Bug 821671 - libXv

  - Bug 821670 - libXt

  - Bug 821669 - libXrender

  - Bug 821668 - libXp

  - Bug 821667 - libXfixes

  - Bug 821665 - libXext

  - Bug 821663 - libFS, libXcursor, libXi, libXinerama,
    libXRes, libXtst, libXvMC, libXxf86dga, libXxf86vm,
    libdmx"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1982.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1983.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1984.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1985.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1987.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1988.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1989.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1990.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1991.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1992.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1996.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1997.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1998.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1999.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2066.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8623.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-Xnest-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-Xvfb-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-Xvnc-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-devel-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-fonts-100dpi-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-fonts-75dpi-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-fonts-cyrillic-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-fonts-scalable-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-fonts-syriac-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-libs-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-man-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-server-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"xorg-x11-server-glx-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xorg-x11-devel-32bit-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-Xnest-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-Xvfb-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-Xvnc-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-devel-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-doc-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-fonts-100dpi-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-fonts-75dpi-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-fonts-cyrillic-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-fonts-scalable-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-fonts-syriac-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-libs-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-man-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-sdk-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-server-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"xorg-x11-server-glx-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xorg-x11-devel-32bit-6.9.0-50.84.4")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"xorg-x11-libs-32bit-6.9.0-50.84.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
