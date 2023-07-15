#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135546);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2018-16391",
    "CVE-2018-16392",
    "CVE-2018-16393",
    "CVE-2018-16418",
    "CVE-2018-16419",
    "CVE-2018-16420",
    "CVE-2018-16421",
    "CVE-2018-16422",
    "CVE-2018-16423",
    "CVE-2018-16426",
    "CVE-2018-16427"
  );

  script_name(english:"EulerOS 2.0 SP3 : opensc (EulerOS-SA-2020-1417)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the opensc package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Several buffer overflows when handling responses from a
    Muscle Card in muscle_list_files in
    libopensc/card-muscle.c in OpenSC before 0.19.0-rc1
    could be used by attackers able to supply crafted
    smartcards to cause a denial of service (application
    crash) or possibly have unspecified other
    impact.(CVE-2018-16391)

  - Several buffer overflows when handling responses from a
    TCOS Card in tcos_select_file in libopensc/card-tcos.c
    in OpenSC before 0.19.0-rc1 could be used by attackers
    able to supply crafted smartcards to cause a denial of
    service (application crash) or possibly have
    unspecified other impact.(CVE-2018-16392)

  - Several buffer overflows when handling responses from a
    Gemsafe V1 Smartcard in gemsafe_get_cert_len in
    libopensc/pkcs15-gemsafeV1.c in OpenSC before
    0.19.0-rc1 could be used by attackers able to supply
    crafted smartcards to cause a denial of service
    (application crash) or possibly have unspecified other
    impact.(CVE-2018-16393)

  - A buffer overflow when handling string concatenation in
    util_acl_to_str in tools/util.c in OpenSC before
    0.19.0-rc1 could be used by attackers able to supply
    crafted smartcards to cause a denial of service
    (application crash) or possibly have unspecified other
    impact.(CVE-2018-16418)

  - Several buffer overflows when handling responses from a
    Cryptoflex card in read_public_key in
    tools/cryptoflex-tool.c in OpenSC before 0.19.0-rc1
    could be used by attackers able to supply crafted
    smartcards to cause a denial of service (application
    crash) or possibly have unspecified other
    impact.(CVE-2018-16419)

  - Several buffer overflows when handling responses from
    an ePass 2003 Card in decrypt_response in
    libopensc/card-epass2003.c in OpenSC before 0.19.0-rc1
    could be used by attackers able to supply crafted
    smartcards to cause a denial of service (application
    crash) or possibly have unspecified other
    impact.(CVE-2018-16420)

  - Several buffer overflows when handling responses from a
    CAC Card in cac_get_serial_nr_from_CUID in
    libopensc/card-cac.c in OpenSC before 0.19.0-rc1 could
    be used by attackers able to supply crafted smartcards
    to cause a denial of service (application crash) or
    possibly have unspecified other impact.(CVE-2018-16421)

  - A single byte buffer overflow when handling responses
    from an esteid Card in sc_pkcs15emu_esteid_init in
    libopensc/pkcs15-esteid.c in OpenSC before 0.19.0-rc1
    could be used by attackers able to supply crafted
    smartcards to cause a denial of service (application
    crash) or possibly have unspecified other
    impact.(CVE-2018-16422)

  - A double free when handling responses from a smartcard
    in sc_file_set_sec_attr in libopensc/sc.c in OpenSC
    before 0.19.0-rc1 could be used by attackers able to
    supply crafted smartcards to cause a denial of service
    (application crash) or possibly have unspecified other
    impact.(CVE-2018-16423)

  - Endless recursion when handling responses from an
    IAS-ECC card in iasecc_select_file in
    libopensc/card-iasecc.c in OpenSC before 0.19.0-rc1
    could be used by attackers able to supply crafted
    smartcards to hang or crash the opensc library using
    programs.(CVE-2018-16426)

  - Various out of bounds reads when handling responses in
    OpenSC before 0.19.0-rc1 could be used by attackers
    able to supply crafted smartcards to potentially crash
    the opensc library using programs.(CVE-2018-16427)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1417
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69743efa");
  script_set_attribute(attribute:"solution", value:
"Update the affected opensc packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16423");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:opensc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["opensc-0.16.0-5.20170227git777e2a3.h1"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "opensc");
}
