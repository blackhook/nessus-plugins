#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0106 and 
# CentOS Errata and Security Advisory 2007:0106 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24764);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1263");
  script_bugtraq_id(22757);
  script_xref(name:"RHSA", value:"2007:0106");

  script_name(english:"CentOS 3 / 4 : gnupg (CESA-2007:0106)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated GnuPG packages that fix a security issue are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

GnuPG is a utility for encrypting data and creating digital
signatures.

Gerardo Richarte discovered that a number of applications that make
use of GnuPG are prone to a vulnerability involving incorrect
verification of signatures and encryption. An attacker could add
arbitrary content to a signed message in such a way that a receiver of
the message would not be able to distinguish between the properly
signed parts of a message and the forged, unsigned, parts.
(CVE-2007-1263)

Whilst this is not a vulnerability in GnuPG itself, the GnuPG team
have produced a patch to protect against messages with multiple
plaintext packets. Users should update to these erratum packages which
contain the backported patch for this issue.

Red Hat would like to thank Core Security Technologies for reporting
this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013592.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b92f661a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013593.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af27678a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013594.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edfcf107"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013597.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58cbc53c"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013601.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9436921a"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-March/013602.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4599b1a1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gnupg package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/06");
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
if (! preg(pattern:"^(3|4)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x / 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"gnupg-1.2.1-20")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gnupg-1.2.6-9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnupg");
}
