#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0222. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131422);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/18");

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
  script_bugtraq_id(
    107519,
    107573,
    107575,
    107576,
    108109,
    108112
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : opensc Multiple Vulnerabilities (NS-SA-2019-0222)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has opensc packages installed that are affected by
multiple vulnerabilities:

  - Several buffer overflows when handling responses from a
    Muscle Card in muscle_list_files in libopensc/card-
    muscle.c in OpenSC before 0.19.0-rc1 could be used by
    attackers able to supply crafted smartcards to cause a
    denial of service (application crash) or possibly have
    unspecified other impact. (CVE-2018-16391)

  - Several buffer overflows when handling responses from a
    TCOS Card in tcos_select_file in libopensc/card-tcos.c
    in OpenSC before 0.19.0-rc1 could be used by attackers
    able to supply crafted smartcards to cause a denial of
    service (application crash) or possibly have unspecified
    other impact. (CVE-2018-16392)

  - Several buffer overflows when handling responses from a
    Gemsafe V1 Smartcard in gemsafe_get_cert_len in
    libopensc/pkcs15-gemsafeV1.c in OpenSC before 0.19.0-rc1
    could be used by attackers able to supply crafted
    smartcards to cause a denial of service (application
    crash) or possibly have unspecified other impact.
    (CVE-2018-16393)

  - A buffer overflow when handling string concatenation in
    util_acl_to_str in tools/util.c in OpenSC before
    0.19.0-rc1 could be used by attackers able to supply
    crafted smartcards to cause a denial of service
    (application crash) or possibly have unspecified other
    impact. (CVE-2018-16418)

  - Several buffer overflows when handling responses from a
    Cryptoflex card in read_public_key in tools/cryptoflex-
    tool.c in OpenSC before 0.19.0-rc1 could be used by
    attackers able to supply crafted smartcards to cause a
    denial of service (application crash) or possibly have
    unspecified other impact. (CVE-2018-16419)

  - A single byte buffer overflow when handling responses
    from an esteid Card in sc_pkcs15emu_esteid_init in
    libopensc/pkcs15-esteid.c in OpenSC before 0.19.0-rc1
    could be used by attackers able to supply crafted
    smartcards to cause a denial of service (application
    crash) or possibly have unspecified other impact.
    (CVE-2018-16422)

  - A double free when handling responses from a smartcard
    in sc_file_set_sec_attr in libopensc/sc.c in OpenSC
    before 0.19.0-rc1 could be used by attackers able to
    supply crafted smartcards to cause a denial of service
    (application crash) or possibly have unspecified other
    impact. (CVE-2018-16423)

  - Several buffer overflows when handling responses from an
    ePass 2003 Card in decrypt_response in libopensc/card-
    epass2003.c in OpenSC before 0.19.0-rc1 could be used by
    attackers able to supply crafted smartcards to cause a
    denial of service (application crash) or possibly have
    unspecified other impact. (CVE-2018-16420)

  - Several buffer overflows when handling responses from a
    CAC Card in cac_get_serial_nr_from_CUID in
    libopensc/card-cac.c in OpenSC before 0.19.0-rc1 could
    be used by attackers able to supply crafted smartcards
    to cause a denial of service (application crash) or
    possibly have unspecified other impact. (CVE-2018-16421)

  - Endless recursion when handling responses from an IAS-
    ECC card in iasecc_select_file in libopensc/card-
    iasecc.c in OpenSC before 0.19.0-rc1 could be used by
    attackers able to supply crafted smartcards to hang or
    crash the opensc library using programs.
    (CVE-2018-16426)

  - Various out of bounds reads when handling responses in
    OpenSC before 0.19.0-rc1 could be used by attackers able
    to supply crafted smartcards to potentially crash the
    opensc library using programs. (CVE-2018-16427)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0222");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL opensc packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16423");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16393");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "opensc-0.19.0-3.el7",
    "opensc-debuginfo-0.19.0-3.el7"
  ],
  "CGSL MAIN 5.04": [
    "opensc-0.19.0-3.el7",
    "opensc-debuginfo-0.19.0-3.el7"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
