#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124942);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-6272",
    "CVE-2016-10195",
    "CVE-2016-10196",
    "CVE-2016-10197"
  );
  script_bugtraq_id(
    71971
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : libevent (EulerOS-SA-2019-1439)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libevent package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Multiple integer overflows in the evbuffer API in
    Libevent 1.4.x before 1.4.15, 2.0.x before 2.0.22, and
    2.1.x before 2.1.5-beta allow context-dependent
    attackers to cause a denial of service or possibly have
    other unspecified impact via 'insanely large inputs' to
    the (1) evbuffer_add, (2) evbuffer_expand, or (3)
    bufferevent_write function, which triggers a heap-based
    buffer overflow or an infinite loop. NOTE: this
    identifier has been SPLIT per ADT3 due to different
    affected versions. See CVE-2015-6525 for the functions
    that are only affected in 2.0 and later.(CVE-2014-6272)

  - An out of bounds read vulnerability was found in
    libevent in the search_make_new function. If an
    attacker could cause an application using libevent to
    attempt resolving an empty hostname, an out of bounds
    read could occur possibly leading to a
    crash.(CVE-2016-10197)

  - A vulnerability was found in libevent with the parsing
    of DNS requests and replies. An attacker could send a
    forged DNS response to an application using libevent
    which could lead to reading data out of bounds on the
    heap, potentially disclosing a small amount of
    application memory.(CVE-2016-10195)

  - A vulnerability was found in libevent with the parsing
    of IPv6 addresses. If an attacker could cause an
    application using libevent to parse a malformed address
    in IPv6 notation of more than 2GiB in length, a stack
    overflow would occur leading to a
    crash.(CVE-2016-10196)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1439
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb568ab2");
  script_set_attribute(attribute:"solution", value:
"Update the affected libevent packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-10195");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libevent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libevent-2.0.21-4.h5.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libevent");
}
