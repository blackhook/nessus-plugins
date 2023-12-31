#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandrake Linux Security Advisory MDKSA-2005:129. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19889);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-1268", "CVE-2005-2088");
  script_bugtraq_id(14106, 14366);
  script_xref(name:"MDKSA", value:"2005:129");

  script_name(english:"Mandrake Linux Security Advisory : apache2 (MDKSA-2005:129)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandrake Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Marc Stern reported an off-by-one overflow in the mod_ssl CRL
verification callback which can only be exploited if the Apache server
is configured to use a malicious certificate revocation list
(CVE-2005-1268).

Watchfire reported a flaw that occured when using the Apache server as
a HTTP proxy. A remote attacker could send an HTTP request with both a
'Transfer-Encoding: chunked' header and a 'Content-Length' header
which would cause Apache to incorrectly handle and forward the body of
the request in a way that the receiving server processed it as a
separate HTTP request. This could be used to allow the bypass of web
application firewall protection or lead to cross-site scripting (XSS)
attacks (CVE-2005-2088).

The updated packages have been patched to prevent these issues."
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_dav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_disk_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_file_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_mem_cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-peruser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64apr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libapr0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandrakesoft:mandrake_linux:10.1");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:mandrakesoft:mandrake_linux:le2005");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"MDK10.0", reference:"apache2-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-common-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-devel-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-manual-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_cache-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_dav-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_deflate-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_disk_cache-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_file_cache-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_ldap-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_mem_cache-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_proxy-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-mod_ssl-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-modules-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", reference:"apache2-source-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"amd64", reference:"lib64apr0-2.0.48-6.9.100mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.0", cpu:"i386", reference:"libapr0-2.0.48-6.9.100mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.1", reference:"apache2-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-common-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-devel-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-manual-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_cache-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_dav-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_deflate-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_disk_cache-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_file_cache-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_ldap-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_mem_cache-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_proxy-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-mod_ssl-2.0.50-4.2.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-modules-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-source-2.0.50-7.3.101mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.1", reference:"apache2-worker-2.0.50-7.3.101mdk", yank:"mdk")) flag++;

if (rpm_check(release:"MDK10.2", reference:"apache2-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-common-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-devel-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-manual-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_cache-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_dav-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_deflate-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_disk_cache-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_file_cache-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_ldap-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_mem_cache-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_proxy-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-mod_ssl-2.0.53-8.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-modules-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-peruser-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-source-2.0.53-9.1.102mdk", yank:"mdk")) flag++;
if (rpm_check(release:"MDK10.2", reference:"apache2-worker-2.0.53-9.1.102mdk", yank:"mdk")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
