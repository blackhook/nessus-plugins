#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1343.
#

include("compat.inc");

if (description)
{
  script_id(130402);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/17");

  script_cve_id("CVE-2018-16838", "CVE-2019-3811");
  script_xref(name:"ALAS", value:"2019-1343");

  script_name(english:"Amazon Linux 2 : sssd (ALAS-2019-1343)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in sssd Group Policy Objects implementation. When the
GPO is not readable by SSSD due to a too strict permission settings on
the server side, SSSD will allow all authenticated users to login
instead of denying access.(CVE-2018-16838)

A vulnerability was found in sssd where, if a user was configured with
no home directory set, sssd would return '/' (the root directory)
instead of '' (the empty string / no home directory). This could
impact services that restrict the user's filesystem access to within
their home directory through chroot().(CVE-2019-3811)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1343.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update sssd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-kcm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-libwbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-polkit-rules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"libipa_hbac-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libipa_hbac-devel-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_autofs-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_certmap-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_certmap-devel-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_idmap-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_idmap-devel-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_nss_idmap-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_nss_idmap-devel-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_simpleifp-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_simpleifp-devel-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libsss_sudo-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"python-libipa_hbac-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"python-libsss_nss_idmap-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"python-sss-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"python-sss-murmur-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"python-sssdconfig-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-ad-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-client-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-common-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-common-pac-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-dbus-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-debuginfo-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-ipa-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-kcm-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-krb5-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-krb5-common-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-ldap-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-libwbclient-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-libwbclient-devel-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-polkit-rules-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-proxy-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-tools-1.16.4-21.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"sssd-winbind-idmap-1.16.4-21.amzn2")) flag++;

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
