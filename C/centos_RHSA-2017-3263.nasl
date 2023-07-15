#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:3263 and 
# CentOS Errata and Security Advisory 2017:3263 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104790);
  script_version("3.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-1000257");
  script_xref(name:"RHSA", value:"2017:3263");

  script_name(english:"CentOS 7 : curl (CESA-2017:3263)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for curl is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The curl packages provide the libcurl library and the curl utility for
downloading files from servers using various protocols, including
HTTP, FTP, and LDAP.

Security Fix(es) :

* A buffer overrun flaw was found in the IMAP handler of libcurl. By
tricking an unsuspecting user into connecting to a malicious IMAP
server, an attacker could exploit this flaw to potentially cause
information disclosure or crash the application. (CVE-2017-1000257)

Red Hat would like to thank the Curl project for reporting this issue.
Upstream acknowledges Brian Carpenter and the OSS-Fuzz project as the
original reporters."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-November/022630.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29e0c499"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000257");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"curl-7.29.0-42.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcurl-7.29.0-42.el7_4.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libcurl-devel-7.29.0-42.el7_4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl / libcurl-devel");
}
