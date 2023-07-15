#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0444 and 
# CentOS Errata and Security Advisory 2009:0444 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43744);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-2974", "CVE-2005-3350");
  script_bugtraq_id(15299, 15304);
  script_xref(name:"RHSA", value:"2009:0444");

  script_name(english:"CentOS 5 : giflib (CESA-2009:0444)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated giflib packages that fix several security issues are now
available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The giflib packages contain a shared library of functions for loading
and saving GIF image files. This library is API and ABI compatible
with libungif, the library that supported uncompressed GIF image files
while the Unisys LZW patent was in effect.

Several flaws were discovered in the way giflib decodes GIF images. An
attacker could create a carefully crafted GIF image that could cause
an application using giflib to crash or, possibly, execute arbitrary
code when opened by a victim. (CVE-2005-2974, CVE-2005-3350)

All users of giflib are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. All running
applications using giflib must be restarted for the update to take
effect."
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015828.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d20e96eb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2009-April/015829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38dd7f06"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected giflib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:giflib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:giflib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:giflib-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-5", reference:"giflib-4.1.3-7.1.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"giflib-devel-4.1.3-7.1.el5_3.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"giflib-utils-4.1.3-7.1.el5_3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "giflib / giflib-devel / giflib-utils");
}
