#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1312.
#

include("compat.inc");

if (description)
{
  script_id(129794);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

  script_cve_id("CVE-2018-16391", "CVE-2018-16392", "CVE-2018-16393", "CVE-2018-16418", "CVE-2018-16419", "CVE-2018-16420", "CVE-2018-16421", "CVE-2018-16422", "CVE-2018-16423", "CVE-2018-16426", "CVE-2018-16427");
  script_xref(name:"ALAS", value:"2019-1312");

  script_name(english:"Amazon Linux 2 : opensc (ALAS-2019-1312)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several buffer overflows when handling responses from a Muscle Card in
muscle_list_files in libopensc/card-muscle.c in OpenSC before
0.19.0-rc1 could be used by attackers able to supply crafted
smartcards to cause a denial of service (application crash) or
possibly have unspecified other impact.(CVE-2018-16391)

Several buffer overflows when handling responses from a TCOS Card in
tcos_select_file in libopensc/card-tcos.c in OpenSC before 0.19.0-rc1
could be used by attackers able to supply crafted smartcards to cause
a denial of service (application crash) or possibly have unspecified
other impact.(CVE-2018-16392)

Several buffer overflows when handling responses from a Gemsafe V1
Smartcard in gemsafe_get_cert_len in libopensc/pkcs15-gemsafeV1.c in
OpenSC before 0.19.0-rc1 could be used by attackers able to supply
crafted smartcards to cause a denial of service (application crash) or
possibly have unspecified other impact.CVE-2018-16393)

A buffer overflow when handling string concatenation in
util_acl_to_str in tools/util.c in OpenSC before 0.19.0-rc1 could be
used by attackers able to supply crafted smartcards to cause a denial
of service (application crash) or possibly have unspecified other
impact.(CVE-2018-16418)

Several buffer overflows when handling responses from a Cryptoflex
card in read_public_key in tools/cryptoflex-tool.c in OpenSC before
0.19.0-rc1 could be used by attackers able to supply crafted
smartcards to cause a denial of service (application crash) or
possibly have unspecified other impact.(CVE-2018-16419)

Several buffer overflows when handling responses from an ePass 2003
Card in decrypt_response in libopensc/card-epass2003.c in OpenSC
before 0.19.0-rc1 could be used by attackers able to supply crafted
smartcards to cause a denial of service (application crash) or
possibly have unspecified other impact.(CVE-2018-16420)

Several buffer overflows when handling responses from a CAC Card in
cac_get_serial_nr_from_CUID in libopensc/card-cac.c in OpenSC before
0.19.0-rc1 could be used by attackers able to supply crafted
smartcards to cause a denial of service (application crash) or
possibly have unspecified other impact.(CVE-2018-16421)

A single byte buffer overflow when handling responses from an esteid
Card in sc_pkcs15emu_esteid_init in libopensc/pkcs15-esteid.c in
OpenSC before 0.19.0-rc1 could be used by attackers able to supply
crafted smartcards to cause a denial of service (application crash) or
possibly have unspecified other impact.(CVE-2018-16422)

A double free when handling responses from a smartcard in
sc_file_set_sec_attr in libopensc/sc.c in OpenSC before 0.19.0-rc1
could be used by attackers able to supply crafted smartcards to cause
a denial of service (application crash) or possibly have unspecified
other impact.(CVE-2018-16423)

Endless recursion when handling responses from an IAS-ECC card in
iasecc_select_file in libopensc/card-iasecc.c in OpenSC before
0.19.0-rc1 could be used by attackers able to supply crafted
smartcards to hang or crash the opensc library using
programs.(CVE-2018-16426)

Various out of bounds reads when handling responses in OpenSC before
0.19.0-rc1 could be used by attackers able to supply crafted
smartcards to potentially crash the opensc library using
programs.(CVE-2018-16427)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1312.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update opensc' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16423");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:opensc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:opensc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"AL2", reference:"opensc-0.19.0-3.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"opensc-debuginfo-0.19.0-3.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensc / opensc-debuginfo");
}
