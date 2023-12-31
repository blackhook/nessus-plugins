#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0195 and 
# CentOS Errata and Security Advisory 2006:0195 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21889);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-1918");
  script_bugtraq_id(5834);
  script_xref(name:"RHSA", value:"2006:0195");

  script_name(english:"CentOS 3 : tar (CESA-2006:0195)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated tar package that fixes a path traversal flaw is now
available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The GNU tar program saves many files together in one archive and can
restore individual files (or all of the files) from that archive.

In 2002, a path traversal flaw was found in the way GNU tar extracted
archives. A malicious user could create a tar archive that could write
to arbitrary files to which the user running GNU tar has write access
(CVE-2002-0399). Red Hat included a backported security patch to
correct this issue in Red Hat Enterprise Linux 3, and an erratum for
Red Hat Enterprise Linux 2.1 users was issued.

During internal testing, we discovered that our backported security
patch contained an incorrect optimization and therefore was not
sufficient to completely correct this vulnerability. The Common
Vulnerabilities and Exposures project (cve.mitre.org) assigned the
name CVE-2005-1918 to this issue.

Users of tar should upgrade to this updated package, which contains a
replacement backported patch to correct this issue."
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-February/012684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5d1a795"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-February/012685.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb2bc5fb"
  );
  # https://lists.centos.org/pipermail/centos-announce/2006-February/012686.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc12a888"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tar package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"tar-1.13.25-14.RHEL3")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tar");
}
