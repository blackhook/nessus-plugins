#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0975 and 
# CentOS Errata and Security Advisory 2007:0975 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(27539);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-4619", "CVE-2007-6277");
  script_bugtraq_id(26042);
  script_xref(name:"RHSA", value:"2007:0975");

  script_name(english:"CentOS 4 / 5 : flac (CESA-2007:0975)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated flac package to correct a security issue is now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

FLAC is a Free Lossless Audio Codec. The flac package consists of a
FLAC encoder and decoder in library form, a program to encode and
decode FLAC files, a metadata editor for FLAC files and input plugins
for various music players.

A security flaw was found in the way flac processed audio data. An
attacker could create a carefully crafted FLAC audio file in such a
way that it could cause an application linked with flac libraries to
crash or execute arbitrary code when it was opened. (CVE-2007-4619)

Users of flac are advised to upgrade to this updated package, which
contains a backported patch that resolves this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014331.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66fd83e4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014340.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?183d061e"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014341.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8910d5a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014346.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?264668f4"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-October/014347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5975d33d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected flac packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:flac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:flac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xmms-flac");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"flac-1.1.0-7.el4_5.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"flac-1.1.0-7.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"flac-1.1.0-7.el4_5.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"flac-devel-1.1.0-7.el4_5.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"flac-devel-1.1.0-7.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"flac-devel-1.1.0-7.el4_5.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"xmms-flac-1.1.0-7.c4.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"flac-1.1.2-28.el5_0.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"flac-devel-1.1.2-28.el5_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flac / flac-devel / xmms-flac");
}
