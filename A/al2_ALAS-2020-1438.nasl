#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2020-1438.
#

include("compat.inc");

if (description)
{
  script_id(137569);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/22");

  script_cve_id("CVE-2018-11362", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14368", "CVE-2018-16057", "CVE-2018-19622", "CVE-2018-7418");
  script_xref(name:"ALAS", value:"2020-1438");

  script_name(english:"Amazon Linux 2 : wireshark (ALAS-2020-1438)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"In Wireshark 2.6.0 to 2.6.2, 2.4.0 to 2.4.8, and 2.2.0 to 2.2.16, the
Radiotap dissector could crash. This was addressed in
epan/dissectors/packet-ieee80211-radiotap-iter.c by validating
iterator operations. (CVE-2018-16057)

In Wireshark 2.6.0 to 2.6.4 and 2.4.0 to 2.4.10, the MMSE dissector
could go into an infinite loop. This was addressed in
epan/dissectors/packet-mmse.c by preventing length overflows.
(CVE-2018-19622)

In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, the
Bazaar protocol dissector could go into an infinite loop. This was
addressed in epan/dissectors/packet-bzr.c by properly handling items
that are too long. (CVE-2018-14368 )

In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15,
dissectors that support zlib decompression could crash. This was
addressed in epan/tvbuff_zlib.c by rejecting negative lengths to avoid
a buffer over-read. (CVE-2018-14340)

In Wireshark 2.6.0 to 2.6.1, 2.4.0 to 2.4.7, and 2.2.0 to 2.2.15, the
DICOM dissector could go into a large or infinite loop. This was
addressed in epan/dissectors/packet-dcm.c by preventing an offset
overflow. (CVE-2018-14341)

In Wireshark 2.6.0, 2.4.0 to 2.4.6, and 2.2.0 to 2.2.14, the LDSS
dissector could crash. This was addressed in
epan/dissectors/packet-ldss.c by avoiding a buffer over-read upon
encountering a missing '\0' character. (CVE-2018-11362)

In Wireshark 2.2.0 to 2.2.12 and 2.4.0 to 2.4.4, the SIGCOMP dissector
could crash. This was addressed in epan/dissectors/packet-sigcomp.c by
correcting the extraction of the length value. (CVE-2018-7418)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2020-1438.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update wireshark' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:wireshark-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"wireshark-1.10.14-24.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"wireshark-debuginfo-1.10.14-24.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"wireshark-devel-1.10.14-24.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"wireshark-gnome-1.10.14-24.amzn2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wireshark / wireshark-debuginfo / wireshark-devel / wireshark-gnome");
}
