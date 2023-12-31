#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-2521.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27775);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-5269");
  script_bugtraq_id(25956);
  script_xref(name:"FEDORA", value:"2007-2521");
  script_xref(name:"Secunia", value:"27093");

  script_name(english:"Fedora 7 : libpng10-1.0.29-1.fc7 (2007-2521)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Certain chunk handlers in libpng10 before 1.0.29 allow remote
attackers to cause a denial of service (crash) via crafted (1) pCAL
(png_handle_pCAL), (2) sCAL (png_handle_sCAL), (3) tEXt
(png_push_read_tEXt), (4) iTXt (png_handle_iTXt), and (5) ztXT
(png_handle_ztXt) chunking in PNG images, which trigger out-of-bounds
read operations.

http://secunia.com/advisories/27093
http://www.frsirt.com/english/advisories/2007/3390
http://sourceforge.net/mailarchive/forum.php?thread_name=3.0.6.32.2007
1004082318.012a7628%40mail.comcast.net&forum_name=png-mng-implement

This update to 1.0.29 addresses these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://sourceforge.net/mailarchive/forum.php?thread_name=3.0.6.32.20071004082318.012a7628%40mail.comcast.net&forum_name=png-mng-implement
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f1f637b"
  );
  # http://www.frsirt.com/english/advisories/2007/3390
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.frsirt.com"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=327791"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-October/004323.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bda214f1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libpng10, libpng10-debuginfo and / or
libpng10-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng10-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"libpng10-1.0.29-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libpng10-debuginfo-1.0.29-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"libpng10-devel-1.0.29-1.fc7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng10 / libpng10-debuginfo / libpng10-devel");
}
