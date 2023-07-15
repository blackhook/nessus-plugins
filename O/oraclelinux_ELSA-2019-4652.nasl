#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4652.
#

include("compat.inc");

if (description)
{
  script_id(125380);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/15");

  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");

  script_name(english:"Oracle Linux 6 / 7 : curl (ELSA-2019-4652)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[7.29.0-51.0.1]
- Security Fixes [OraBug: 28939992]
- CVE-2016-8615 cookie injection for other servers 
(https://curl.haxx.se/docs/CVE-2016-8615.html)
- CVE-2016-8616 case insensitive password comparison 
(https://curl.haxx.se/docs/CVE-2016-8616.html)
- CVE-2016-8617 OOB write via unchecked multiplication 
(https://curl.haxx.se/docs/CVE-2016-8617.html)
- CVE-2016-8618 double-free in curl_maprintf 
(https://curl.haxx.se/docs/CVE-2016-8618.html)
- CVE-2016-8619 double-free in krb5 code 
(https://curl.haxx.se/docs/CVE-2016-8619.html)
- CVE-2016-8621 curl_getdate read out of bounds 
(https://curl.haxx.se/docs/CVE-2016-8621.html)
- CVE-2016-8622 URL unescape heap overflow via integer truncation 
(https://curl.haxx.se/docs/CVE-2016-8622.html)
- CVE-2016-8623 Use-after-free via shared cookies 
(https://curl.haxx.se/docs/CVE-2016-8623.html)
- CVE-2016-8624 invalid URL parsing with # 
(https://curl.haxx.se/docs/CVE-2016-8624.html)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-May/008755.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-May/008756.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"curl-7.19.7-53.0.2.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"libcurl-7.19.7-53.0.2.el6_9")) flag++;
if (rpm_check(release:"EL6", reference:"libcurl-devel-7.19.7-53.0.2.el6_9")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"curl-7.29.0-51.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcurl-7.29.0-51.0.1.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libcurl-devel-7.29.0-51.0.1.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl / libcurl-devel");
}
