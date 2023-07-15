#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-369.
#

include("compat.inc");

if (description)
{
  script_id(78312);
  script_version("1.6");
  script_cvs_date("Date: 2018/04/18 15:09:35");

  script_cve_id("CVE-2014-2532", "CVE-2014-2653");
  script_xref(name:"ALAS", value:"2014-369");

  script_name(english:"Amazon Linux AMI : openssh (ALAS-2014-369)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"sshd in OpenSSH before 6.6 does not properly support wildcards on
AcceptEnv lines in sshd_config, which allows remote attackers to
bypass intended environment restrictions by using a substring located
before a wildcard character.

The verify_host_key function in sshconnect.c in the client in OpenSSH
6.6 and earlier allows remote servers to trigger the skipping of SSHFP
DNS RR checking by presenting an unacceptable HostCertificate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-369.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssh' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
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
if (rpm_check(release:"ALA", reference:"openssh-6.2p2-8.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-clients-6.2p2-8.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-debuginfo-6.2p2-8.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-keycat-6.2p2-8.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-ldap-6.2p2-8.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssh-server-6.2p2-8.41.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"pam_ssh_agent_auth-0.9.3-5.8.41.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh / openssh-clients / openssh-debuginfo / openssh-keycat / etc");
}
