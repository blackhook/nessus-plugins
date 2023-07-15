#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2018-0264.
#

include("compat.inc");

if (description)
{
  script_id(118051);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/10");

  script_cve_id("CVE-2018-12384");

  script_name(english:"OracleVM 3.3 / 3.4 : nss (OVMSA-2018-0264)");
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

  - Added nss-vendor.patch to change vendor

  - Temporarily disable some tests until expired
    PayPalEE.cert is renewed

  - Backport upstream fix for (CVE-2018-12384)

  - Remove nss-lockcert-api-change.patch, which turned out
    to be a mistake (the symbol was not exported from
    libnss)

  - Restore CERT_LockCertTrust and CERT_UnlockCertTrust back
    in cert.h

  - rebuild

  - Keep legacy code signing trust flags for backwards
    compatibility

  - Decrease the iteration count of PKCS#12 for
    compatibility with Windows

  - Fix deadlock when a token is re-inserted while a client
    process is running

  - Ignore tests which only works with newer nss-softokn

  - Use the correct tarball of NSS 3.36 release

  - Ignore EncryptDeriveTest which only works with newer
    nss-softokn

  - Don't skip non-FIPS and ECC test cases in ssl.sh

  - Rebase to NSS 3.36.0

  - Rebase to NSS 3.36.0 BETA

  - Remove upstreamed nss-is-token-present-race.patch

  - Revert the upstream changes that default to sql database

  - Replace race.patch and nss-3.16-token-init-race.patch
    with a proper upstream fix

  - Don't restrict nss_cycles to sharedb

  - Rebase to NSS 3.34.0"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-October/000895.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b587c29b"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2018-October/000898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f394e86a"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected nss / nss-sysinit / nss-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12384");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"OVS3.3", reference:"nss-3.36.0-9.0.1.el6_10")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-sysinit-3.36.0-9.0.1.el6_10")) flag++;
if (rpm_check(release:"OVS3.3", reference:"nss-tools-3.36.0-9.0.1.el6_10")) flag++;

if (rpm_check(release:"OVS3.4", reference:"nss-3.36.0-9.0.1.el6_10")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-sysinit-3.36.0-9.0.1.el6_10")) flag++;
if (rpm_check(release:"OVS3.4", reference:"nss-tools-3.36.0-9.0.1.el6_10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-sysinit / nss-tools");
}
