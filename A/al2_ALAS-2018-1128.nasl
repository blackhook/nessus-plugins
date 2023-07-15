#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1128.
#

include("compat.inc");

if (description)
{
  script_id(119783);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/27");

  script_cve_id("CVE-2018-10911");
  script_xref(name:"ALAS", value:"2018-1128");

  script_name(english:"Amazon Linux 2 : glusterfs (ALAS-2018-1128)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in dict.c:dict_unserialize function of glusterfs,
dic_unserialize function does not handle negative key length values.
An attacker could use this flaw to read memory from other locations
into the stored dict value.(CVE-2018-10911)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1128.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update glusterfs' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-api-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:glusterfs-rdma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python2-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"glusterfs-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-api-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-api-devel-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-cli-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-client-xlators-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-debuginfo-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-devel-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-fuse-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-libs-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"glusterfs-rdma-3.12.2-18.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"python2-gluster-3.12.2-18.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs / glusterfs-api / glusterfs-api-devel / glusterfs-cli / etc");
}
