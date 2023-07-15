#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2020-0035.
#

include("compat.inc");

if (description)
{
  script_id(140168);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/04");

  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8621", "CVE-2016-8623", "CVE-2016-8624", "CVE-2019-5482");

  script_name(english:"OracleVM 3.4 : curl (OVMSA-2020-0035)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - Fix TFTP small blocksize heap buffer overflow 

462

  - Security Fixes [OraBug: 28939992]

  - CVE-2016-8615 cookie injection for other servers 

  - CVE-2016-8616 case insensitive password comparison 

  - CVE-2016-8617 OOB write via unchecked multiplication 

  - CVE-2016-8618 double-free in curl_maprintf 

  - CVE-2016-8619 double-free in krb5 code 

  - CVE-2016-8621 curl_getdate read out of bounds 

  - CVE-2016-8623 Use-after-free via shared cookies 

  - CVE-2016-8624 invalid URL parsing with # 

  - use PK11_CreateManagedGenericObject in libcurl to
    prevent memory leak 

  - fix auth failure with duplicated WWW-Authenticate header
    (#1757643)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2016-8615.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2016-8616.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2016-8617.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2016-8618.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2016-8619.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2016-8621.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2016-8623.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://curl.haxx.se/docs/CVE-2016-8624.html"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2020-September/000998.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4c2cdb6"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected curl / libcurl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:libcurl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! preg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"curl-7.19.7-54.0.2.el6_10")) flag++;
if (rpm_check(release:"OVS3.4", reference:"libcurl-7.19.7-54.0.2.el6_10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / libcurl");
}
