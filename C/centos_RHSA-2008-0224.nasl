#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0224 and 
# CentOS Errata and Security Advisory 2008:0224 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43680);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2008-1380");
  script_bugtraq_id(28818);
  script_xref(name:"RHSA", value:"2008:0224");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2008:0224)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix a security issue are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A flaw was found in the processing of malformed JavaScript content. An
HTML mail message containing such malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code as the
user running Thunderbird. (CVE-2008-1380)

Note: JavaScript support is disabled by default in Thunderbird; the
above issue is not exploitable unless JavaScript is enabled.

All Thunderbird users should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014878.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ead7a9d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014879.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bffec2f1"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014882.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de11a602"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014883.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b261e65b"
  );
  # https://lists.centos.org/pipermail/centos-announce/2008-May/014892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a67ab6a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/01");
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
if (! preg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x / 5.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.5.0.12-11.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-1.5.0.12-12.el5.centos")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
