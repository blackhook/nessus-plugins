#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2012:058. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58759);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2011-3389", "CVE-2012-0036");
  script_bugtraq_id(49778, 51665);
  script_xref(name:"MDVSA", value:"2012:058");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Mandriva Linux Security Advisory : curl (MDVSA-2012:058)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Mandriva Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"Multiple vulnerabilities has been found and corrected in curl :

curl is vulnerable to a SSL CBC IV vulnerability when built to use
OpenSSL for the SSL/TLS layer. A work-around has been added to
mitigate the problem (CVE-2011-3389).

curl is vulnerable to a data injection attack for certain protocols
through control characters embedded or percent-encoded in URLs
(CVE-2012-0036).

The updated packages have been patched to correct these issues.");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/docs/CVE-2012-0036.html");
  script_set_attribute(attribute:"see_also", value:"http://curl.haxx.se/docs/adv_20120124B.html");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/docs/manpage.html#--ssl-allow-beast");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/libcurl/c/curl_easy_setopt.html#CURLOPTSSLOPTIONS");
  script_set_attribute(attribute:"see_also", value:"http://thread.gmane.org/gmane.comp.web.curl.library/34659");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:curl-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64curl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64curl4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libcurl4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2011");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Mandriva Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"MDK2010.1", reference:"curl-7.20.1-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"curl-examples-7.20.1-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64curl-devel-7.20.1-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64curl4-7.20.1-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libcurl-devel-7.20.1-2.2mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libcurl4-7.20.1-2.2mdv2010.2", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2011", reference:"curl-7.21.7-1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", reference:"curl-examples-7.21.7-1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64curl-devel-7.21.7-1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"x86_64", reference:"lib64curl4-7.21.7-1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libcurl-devel-7.21.7-1.1-mdv2011.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2011", cpu:"i386", reference:"libcurl4-7.21.7-1.1-mdv2011.0", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
