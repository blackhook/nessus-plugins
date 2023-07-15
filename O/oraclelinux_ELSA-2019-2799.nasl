#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:2799 and 
# Oracle Linux Security Advisory ELSA-2019-2799 respectively.
#

include('compat.inc');

if (description)
{
  script_id(129087);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516");
  script_xref(name:"RHSA", value:"2019:2799");
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"Oracle Linux 8 : nginx:1.14 (ELSA-2019-2799) (0-Length Headers Leak) (Data Dribble) (Resource Loop)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2019:2799 :

An update for the nginx:1.14 module is now available for Red Hat
Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Nginx is a web server and a reverse proxy server for HTTP, SMTP, POP3
(Post Office Protocol 3) and IMAP protocols, with a focus on high
concurrency, performance and low memory usage.

Security Fix(es) :

* HTTP/2: large amount of data request leads to denial of service
(CVE-2019-9511)

* HTTP/2: flood using PRIORITY frames resulting in excessive resource
consumption (CVE-2019-9513)

* HTTP/2: 0-length headers leads to denial of service (CVE-2019-9516)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2019-September/009184.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected nginx:1.14 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-all-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nginx-mod-stream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nginx-1.14.1-9.0.1.module+el8.0.0+5347+9282027e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nginx-all-modules-1.14.1-9.0.1.module+el8.0.0+5347+9282027e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nginx-filesystem-1.14.1-9.0.1.module+el8.0.0+5347+9282027e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nginx-mod-http-image-filter-1.14.1-9.0.1.module+el8.0.0+5347+9282027e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nginx-mod-http-perl-1.14.1-9.0.1.module+el8.0.0+5347+9282027e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nginx-mod-http-xslt-filter-1.14.1-9.0.1.module+el8.0.0+5347+9282027e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nginx-mod-mail-1.14.1-9.0.1.module+el8.0.0+5347+9282027e")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nginx-mod-stream-1.14.1-9.0.1.module+el8.0.0+5347+9282027e")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx / nginx-all-modules / nginx-filesystem / etc");
}
