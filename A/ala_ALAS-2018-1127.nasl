#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1127.
#

include("compat.inc");

if (description)
{
  script_id(121360);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2018-10852");
  script_xref(name:"ALAS", value:"2018-1127");

  script_name(english:"Amazon Linux AMI : sssd (ALAS-2018-1127)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The UNIX pipe which sudo uses to contact SSSD and read the available
sudo rules from SSSD utilizes too broad of a set of permissions. Any
user who can send a message using the same raw protocol that sudo and
SSSD use can read the sudo rules available for any user.
(CVE-2018-10852)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1127.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update sssd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_certmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_simpleifp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python27-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"libipa_hbac-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libipa_hbac-devel-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_autofs-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_certmap-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_certmap-devel-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_idmap-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_idmap-devel-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_nss_idmap-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_nss_idmap-devel-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_simpleifp-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_simpleifp-devel-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"libsss_sudo-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libipa_hbac-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-libsss_nss_idmap-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-sss-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-sss-murmur-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"python27-sssdconfig-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-ad-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-client-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-common-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-common-pac-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-dbus-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-debuginfo-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-ipa-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-krb5-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-krb5-common-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-ldap-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-libwbclient-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-libwbclient-devel-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-proxy-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-tools-1.16.2-13.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"sssd-winbind-idmap-1.16.2-13.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libsss_autofs / libsss_certmap / etc");
}
