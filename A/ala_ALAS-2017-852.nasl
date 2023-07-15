#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-852.
#

include("compat.inc");

if (description)
{
  script_id(101064);
  script_version("3.9");
  script_cvs_date("Date: 2018/04/18 15:09:36");

  script_cve_id("CVE-2017-7508", "CVE-2017-7520", "CVE-2017-7521", "CVE-2017-7522");
  script_xref(name:"ALAS", value:"2017-852");

  script_name(english:"Amazon Linux AMI : openvpn (ALAS-2017-852)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OpenVPN versions before 2.4.3 and before 2.3.17 are vulnerable to
remote denial-of-service when receiving malformed IPv6 packet.
(CVE-2017-7508)

OpenVPN versions before 2.4.3 and before 2.3.17 are vulnerable to
denial-of-service by authenticated remote attacker via sending a
certificate with an embedded NULL character. (CVE-2017-7522)

OpenVPN versions before 2.4.3 and before 2.3.17 are vulnerable to
remote denial-of-service due to memory exhaustion caused by memory
leaks and double-free issue in extract_x509_extension().
(CVE-2017-7521)

OpenVPN versions before 2.4.3 and before 2.3.17 are vulnerable to
denial-of-service and/or possibly sensitive memory leak triggered by
man-in-the-middle attacker. (CVE-2017-7520)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-852.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openvpn' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openvpn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openvpn-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

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
if (rpm_check(release:"ALA", reference:"openvpn-2.4.3-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openvpn-debuginfo-2.4.3-1.19.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openvpn-devel-2.4.3-1.19.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn / openvpn-debuginfo / openvpn-devel");
}
