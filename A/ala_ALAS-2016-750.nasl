#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-750.
#

include('compat.inc');

if (description)
{
  script_id(93745);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2016-6329");
  script_xref(name:"ALAS", value:"2016-750");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Amazon Linux AMI : openvpn (ALAS-2016-750) (SWEET32)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux AMI host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Ciphers with 64-bit block sizes used in CBC mode were found to be
vulnerable to a birthday attack when key renegotiation doesn't happen
frequently or at all in long running connections. The blowfish cipher
as used in OpenVPN by default is vulnerable to this attack, allowing a
remote attacker to recover partial plaintext information (XOR of two
plaintext blocks).");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/ALAS-2016-750.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update openvpn' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openvpn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2022 Tenable Network Security, Inc.");

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
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"openvpn-2.3.12-1.16.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openvpn-debuginfo-2.3.12-1.16.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn / openvpn-debuginfo");
}
