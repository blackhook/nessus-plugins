#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0042.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90385);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2016-1950");

  script_name(english:"OracleVM 3.3 / 3.4 : nss / nss-util / etc (OVMSA-2016-0042)");
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

nss

  - Added nss-vendor.patch to change vendor

  - Ensure all ssl.sh tests are executed

  - Ensure abi compatibility

  - Rebase to NSS-3.21

nss-util

  - Rebase RHEL 6.7.z to NSS-util 3.21 in preparation for
    Firefox 45

  - Resolves: Bug 1299874

  - Update upstream patch for (CVE-2016-1950) nspr

  - Rebase to NSPR 4.11"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-April/000453.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40fa2502"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-April/000454.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?232168bc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"nspr-4.11.0-0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-3.21.0-0.3.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-sysinit-3.21.0-0.3.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-tools-3.21.0-0.3.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-util-3.21.0-0.3.el6_7")) flag++;

if (rpm_check(release:"OVS3.4", reference:"nspr-4.11.0-0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-3.21.0-0.3.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-sysinit-3.21.0-0.3.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-tools-3.21.0-0.3.0.1.el6_7")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-util-3.21.0-0.3.el6_7")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nss / nss-sysinit / nss-tools / nss-util");
}
