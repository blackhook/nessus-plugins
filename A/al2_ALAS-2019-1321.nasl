#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1321.
#

include("compat.inc");

if (description)
{
  script_id(130218);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/18");

  script_cve_id("CVE-2017-18233", "CVE-2017-18234", "CVE-2017-18236", "CVE-2017-18238", "CVE-2018-7730");
  script_xref(name:"ALAS", value:"2019-1321");

  script_name(english:"Amazon Linux 2 : exempi (ALAS-2019-1321)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in Exempi before 2.4.4. Integer overflow in
the Chunk class in XMPFiles/source/FormatSupport/RIFF.cpp allows
remote attackers to cause a denial of service (infinite loop) via
crafted XMP data in a .avi file.(CVE-2017-18233)

An issue was discovered in Exempi before 2.4.3. It allows remote
attackers to cause a denial of service (invalid memcpy with resultant
use-after-free) or possibly have unspecified other impact via a .pdf
file containing JPEG data, related to
XMPFiles/source/FormatSupport/ReconcileTIFF.cpp,
XMPFiles/source/FormatSupport/TIFF_MemoryReader.cpp, and
XMPFiles/source/FormatSupport/TIFF_Support.hpp.(CVE-2017-18234)

An issue was discovered in Exempi before 2.4.4. The
ASF_Support::ReadHeaderObject function in
XMPFiles/source/FormatSupport/ASF_Support.cpp allows remote attackers
to cause a denial of service (infinite loop) via a crafted .asf
file.(CVE-2017-18236)

An infinite loop has been discovered in Exempi in the way it handles
Extensible Metadata Platform (XMP) data in QuickTime files. An
attacker could cause a denial of service via a crafted
file.(CVE-2017-18238)

An integer wraparound, leading to a buffer overflow, was found in
Exempi in the way it handles Adobe Photoshop Images. An attacker could
exploit this to cause a denial of service via a crafted image
file.(CVE-2018-7730)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1321.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update exempi' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exempi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exempi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:exempi-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");
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
if (rpm_check(release:"AL2", reference:"exempi-2.2.0-9.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"exempi-debuginfo-2.2.0-9.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"exempi-devel-2.2.0-9.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exempi / exempi-debuginfo / exempi-devel");
}
