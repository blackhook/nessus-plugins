#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2018-cb339851e7.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106465);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376", "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380", "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420");
  script_xref(name:"FEDORA", value:"2018-cb339851e7");

  script_name(english:"Fedora 27 : clamav (2018-cb339851e7)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ClamAV 0.99.3 =============

This release is a security release and is recommended for all ClamAV
users. Please see details below :

1. ClamAV UAF (use-after-free) Vulnerabilities (CVE-2017-12374)

---------------------------------------------------------------

The ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device.

The vulnerability is due to a lack of input validation checking
mechanisms during certain mail parsing operations. If successfully
exploited, the ClamAV software could allow a variable pointing to the
mail body which could cause a used after being free (use-after-free)
instance which may lead to a disruption of services on an affected
device to include a denial of service condition.

  - CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

  - https://bugzilla.clamav.net/show_bug.cgi?id=11939

2. ClamAV Buffer Overflow Vulnerability (CVE-2017-12375)

--------------------------------------------------------

The ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device.

The vulnerability is due to a lack of input validation checking
mechanisms during certain mail parsing functions. An unauthenticated,
remote attacker could exploit this vulnerability by sending a crafted
email to the affected device. This action could cause a buffer
overflow condition when ClamAV scans the malicious email, allowing the
attacker to potentially cause a DoS condition on an affected device.

  - CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N /A:L

  - https://bugzilla.clamav.net/show_bug.cgi?id=11940

3. ClamAV Buffer Overflow in handle_pdfname Vulnerability
(CVE-2017-12376)

----------------------------------------------------------------------
----

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition or potentially execute
arbitrary code on an affected device.

The vulnerability is due to improper input validation checking
mechanisms when handling Portable Document Format (.pdf) files sent to
an affected device. An unauthenticated, remote attacker could exploit
this vulnerability by sending a crafted .pdf file to an affected
device. This action could cause a buffer overflow when ClamAV scans
the malicious file, allowing the attacker to cause a DoS condition or
potentially execute arbitrary code.

  - https://bugzilla.clamav.net/show_bug.cgi?id=11942

  - CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

4. ClamAV Mew Packet Heap Overflow Vulnerability (CVE-2017-12377)

-----------------------------------------------------------------

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition or potentially execute
arbitrary code on an affected device.

The vulnerability is due to improper input validation checking
mechanisms in mew packet files sent to an affected device. A
successful exploit could cause a heap overflow condition when ClamAV
scans the malicious file, allowing the attacker to cause a DoS
condition or potentially execute arbitrary code on the affected
device.

  - https://bugzilla.clamav.net/show_bug.cgi?id=11943

  - CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L /A:L

5. ClamAV Buffer Over Read Vulnerability (CVE-2017-12378)

---------------------------------------------------------

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device.

The vulnerability is due to improper input validation checking
mechanisms of .tar (Tape Archive) files sent to an affected device. A
successful exploit could cause a buffer over-read condition when
ClamAV scans the malicious .tar file, potentially allowing the
attacker to cause a DoS condition on the affected device.

  - https://bugzilla.clamav.net/show_bug.cgi?id=11946

  - CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N /A:L

6. ClamAV Buffer Overflow in messageAddArgument Vulnerability
(CVE-2017-12379)

----------------------------------------------------------------------
--------

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition or potentially execute
arbitrary code on an affected device.

The vulnerability is due to improper input validation checking
mechanisms in the message parsing function on an affected system. An
unauthenticated, remote attacker could exploit this vulnerability by
sending a crafted email to the affected device. This action could
cause a buffer overflow condition when ClamAV scans the malicious
email, allowing the attacker to potentially cause a DoS condition or
execute arbitrary code on an affected device.

  - https://bugzilla.clamav.net/show_bug.cgi?id=11944

  - CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L /A:L

7. ClamAV Null Dereference Vulnerability (CVE-2017-12380)

---------------------------------------------------------

ClamAV AntiVirus software versions 0.99.2 and prior contain a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device.

The vulnerability is due to improper input validation checking
mechanisms during certain mail parsing functions of the ClamAV
software. An unauthenticated, remote attacker could exploit this
vulnerability by sending a crafted email to the affected device. An
exploit could trigger a NULL pointer dereference condition when ClamAV
scans the malicious email, which may result in a DoS condition.

  - https://bugzilla.clamav.net/show_bug.cgi?id=11945

  - CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

Further fixes/changes

---------------------

Also included are 2 minor fixes to properly detect openssl install
locations on FreeBSD 11, and prevent false warnings about zlib 1.2.1#
version numbers.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2018-cb339851e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected clamav package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:27");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^27([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 27", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC27", reference:"clamav-0.99.3-1.fc27")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "clamav");
}
