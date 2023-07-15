#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151309);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/06");

  script_cve_id(
    "CVE-2019-25031",
    "CVE-2019-25032",
    "CVE-2019-25033",
    "CVE-2019-25034",
    "CVE-2019-25035",
    "CVE-2019-25036",
    "CVE-2019-25037",
    "CVE-2019-25038",
    "CVE-2019-25039",
    "CVE-2019-25040",
    "CVE-2019-25041",
    "CVE-2019-25042"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : unbound (EulerOS-SA-2021-2124)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the unbound package installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - A flaw was found in unbound. An out-of-bounds write in
    the rdata_copy function may be abused by a remote
    attacker. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as
    service availability.(CVE-2019-25042)

  - A flaw was found in unbound. A reachable assertion in
    the dname_pkt_copy function can be triggered through
    compressed names. The highest threat from this
    vulnerability is to service
    availability.(CVE-2019-25041)

  - A flaw was found in unbound. An infinite loop in
    dname_pkt_copy function could be triggered by a remote
    attacker. The highest threat from this vulnerability is
    to service availability.(CVE-2019-25040)

  - A flaw was found in unbound. An integer overflow in
    ub_packed_rrset_key function may lead to a buffer
    overflow of the allocated buffer if the size can be
    controlled by an attacker. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as service availability.(CVE-2019-25039)

  - A flaw was found in unbound. An integer overflow in
    dnsc_load_local_data function may lead to a buffer
    overflow of the allocated buffer if the size can be
    controlled by an attacker. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as service availability.(CVE-2019-25038)

  - A flaw was found in unbound. A reachable assertion in
    the dname_pkt_copy function can be triggered by sending
    invalid packets to the server. The highest threat from
    this vulnerability is to service
    availability.(CVE-2019-25037)

  - A flaw was found in unbound. A reachable assertion in
    the synth_cname function can be triggered by sending
    invalid packets to the server. If asserts are disabled
    during compilation, this issue might lead to an
    out-of-bounds write in dname_pkt_copy function. The
    highest threat from this vulnerability is to data
    confidentiality and integrity as well as service
    availability.(CVE-2019-25036)

  - A flaw was found in unbound. An out-of-bounds write in
    the sldns_bget_token_par function may be abused by a
    remote attacker. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as service availability.(CVE-2019-25035)

  - A flaw was found in unbound. An integer overflow in the
    sldns_str2wire_dname_buf_origin function may lead to a
    buffer overflow. The highest threat from this
    vulnerability is to data confidentiality and integrity
    as well as service availability.(CVE-2019-25034)

  - A flaw was found in unbound. An integer overflow in the
    regional allocator via the ALIGN_UP macro may lead to a
    buffer overflow if the size can be controlled by an
    attacker. The highest threat from this vulnerability is
    to data confidentiality and integrity as well as
    service availability.(CVE-2019-25033)

  - A flaw was found in unbound. An integer overflow in
    regional_alloc function may lead to a buffer overflow
    of the allocated buffer if the size can be controlled
    by an attacker and can be big enough. The highest
    threat from this vulnerability is to data
    confidentiality and integrity as well as service
    availability.(CVE-2019-25032)

  - A flaw was found in unbound. The
    create_unbound_ad_servers.sh bash script does not
    properly sanitize input data, which is retrieved using
    an unencrypted, unauthenticated HTTP request, before
    writing the configuration file allowing a
    man-in-the-middle attack. The highest threat from this
    vulnerability is to data integrity and system
    availability.(CVE-2019-25031)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2124
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c85bf820");
  script_set_attribute(attribute:"solution", value:
"Update the affected unbound packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["unbound-libs-1.6.6-1.h5"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unbound");
}
