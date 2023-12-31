#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:106. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74415);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-0195", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(67898, 67899, 67900, 67901);
  script_xref(name:"MDVSA", value:"2014:106");

  script_name(english:"Mandriva Linux Security Advisory : openssl (MDVSA-2014:106)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in 
openssl :

The dtls1_reassemble_fragment function in d1_both.c in OpenSSL before
0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h does not
properly validate fragment lengths in DTLS ClientHello messages, which
allows remote attackers to execute arbitrary code or cause a denial of
service (buffer overflow and application crash) via a long non-initial
fragment (CVE-2014-0195).

The dtls1_get_message_fragment function in d1_both.c in OpenSSL before
0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h allows remote
attackers to cause a denial of service (recursion and client crash)
via a DTLS hello message in an invalid DTLS handshake (CVE-2014-0221).

OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h
does not properly restrict processing of ChangeCipherSpec messages,
which allows man-in-the-middle attackers to trigger use of a
zero-length master key in certain OpenSSL-to-OpenSSL communications,
and consequently hijack sessions or obtain sensitive information, via
a crafted TLS handshake, aka the CCS Injection vulnerability
(CVE-2014-0224).

The ssl3_send_client_key_exchange function in s3_clnt.c in OpenSSL
before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h, when an
anonymous ECDH cipher suite is used, allows remote attackers to cause
a denial of service (NULL pointer dereference and client crash) by
triggering a NULL certificate value (CVE-2014-3470).

The updated packages have been upgraded to the 1.0.0m version where
these security flaws has been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20140605.txt"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-engines1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64openssl1.0.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-devel-1.0.0m-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-engines1.0.0-1.0.0m-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl-static-devel-1.0.0m-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64openssl1.0.0-1.0.0m-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"openssl-1.0.0m-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
