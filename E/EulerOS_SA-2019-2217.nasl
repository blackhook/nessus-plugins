#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130679);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-0799",
    "CVE-2016-2105",
    "CVE-2016-2106",
    "CVE-2016-2109",
    "CVE-2016-2842",
    "CVE-2016-6306"
  );

  script_name(english:"EulerOS 2.0 SP5 : openssl098e (EulerOS-SA-2019-2217)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl098e package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An integer overflow flaw, leading to a buffer overflow,
    was found in the way the EVP_EncodeUpdate() function of
    OpenSSL parsed very large amounts of input data. A
    remote attacker could use this flaw to crash an
    application using OpenSSL or, possibly, execute
    arbitrary code with the permissions of the user running
    that application.(CVE-2016-2105)

  - An integer overflow flaw, leading to a buffer overflow,
    was found in the way the EVP_EncryptUpdate() function
    of OpenSSL parsed very large amounts of input data. A
    remote attacker could use this flaw to crash an
    application using OpenSSL or, possibly, execute
    arbitrary code with the permissions of the user running
    that application.(CVE-2016-2106)

  - A denial of service flaw was found in the way OpenSSL
    parsed certain ASN.1-encoded data from BIO (OpenSSL's
    I/O abstraction) inputs. An application using OpenSSL
    that accepts untrusted ASN.1 BIO input could be forced
    to allocate an excessive amount of data.(CVE-2016-2109)

  - The fmtstr function in crypto/bio/b_print.c in OpenSSL
    1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g improperly
    calculates string lengths, which allows remote
    attackers to cause a denial of service (overflow and
    out-of-bounds read) or possibly have unspecified other
    impact via a long string, as demonstrated by a large
    amount of ASN.1 data, a different vulnerability than
    CVE-2016-2842.(CVE-2016-0799)

  - The certificate parser in OpenSSL before 1.0.1u and
    1.0.2 before 1.0.2i might allow remote attackers to
    cause a denial of service (out-of-bounds read) via
    crafted certificate operations, related to s3_clnt.c
    and s3_srvr.c.(CVE-2016-6306)

  - The doapr_outch function in crypto/bio/b_print.c in
    OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g
    does not verify that a certain memory allocation
    succeeds, which allows remote attackers to cause a
    denial of service (out-of-bounds write or memory
    consumption) or possibly have unspecified other impact
    via a long string, as demonstrated by a large amount of
    ASN.1 data, a different vulnerability than
    CVE-2016-0799.(CVE-2016-2842)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2217
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?660a079a");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl098e packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl098e");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl098e-0.9.8e-29.3.h8.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl098e");
}
