#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1406.
#

include('compat.inc');

if (description)
{
  script_id(134897);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2019-1547", "CVE-2019-1563");
  script_xref(name:"ALAS", value:"2020-1406");

  script_name(english:"Amazon Linux 2 : openssl (ALAS-2020-1406)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Normally in OpenSSL EC groups always have a co-factor present and this
is used in side channel resistant code paths. However, in some cases,
it is possible to construct a group using explicit parameters (instead
of using a named curve). In those cases it is possible that such a
group does not have the cofactor present. This can occur even where
all the parameters match a known named curve. If such a curve is used
then OpenSSL falls back to non-side channel resistant code paths which
may result in full key recovery during an ECDSA signature operation.
In order to be vulnerable an attacker would have to have the ability
to time the creation of a large number of signatures where explicit
parameters with no co-factor present are in use by an application
using libcrypto. For the avoidance of doubt libssl is not vulnerable
because explicit parameters are never used. Fixed in OpenSSL 1.1.1d
(Affected 1.1.1-1.1.1c). Fixed in OpenSSL 1.1.0l (Affected
1.1.0-1.1.0k). Fixed in OpenSSL 1.0.2t (Affected 1.0.2-1.0.2s).
(CVE-2019-1547)

In situations where an attacker receives automated notification of the
success or failure of a decryption attempt an attacker, after sending
a very large number of messages to be decrypted, can recover a
CMS/PKCS7 transported encryption key or decrypt any RSA encrypted
message that was encrypted with the public RSA key, using a
Bleichenbacher padding oracle attack. Applications are not affected if
they use a certificate together with the private RSA key to the
CMS_decrypt or PKCS7_decrypt functions to select the correct recipient
info to decrypt. Fixed in OpenSSL 1.1.1d (Affected 1.1.1-1.1.1c).
Fixed in OpenSSL 1.1.0l (Affected 1.1.0-1.1.0k). Fixed in OpenSSL
1.0.2t (Affected 1.0.2-1.0.2s). (CVE-2019-1563)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1406.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update openssl' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1563");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"openssl-1.0.2k-19.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-debuginfo-1.0.2k-19.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-devel-1.0.2k-19.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-libs-1.0.2k-19.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-perl-1.0.2k-19.amzn2.0.3")) flag++;
if (rpm_check(release:"AL2", reference:"openssl-static-1.0.2k-19.amzn2.0.3")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-libs / etc");
}
