#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2011:121. 
# The text itself is copyright (C) Mandriva S.A.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55709);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2011-2522", "CVE-2011-2694");
  script_xref(name:"MDVSA", value:"2011:121");

  script_name(english:"Mandriva Linux Security Advisory : samba (MDVSA-2011:121)");
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
"Multiple vulnerabilities has been discovered and corrected in samba :

All current released versions of Samba are vulnerable to a cross-site
request forgery in the Samba Web Administration Tool (SWAT). By
tricking a user who is authenticated with SWAT into clicking a
manipulated URL on a different web page, it is possible to manipulate
SWAT (CVE-2011-2522).

All current released versions of Samba are vulnerable to a cross-site
scripting issue in the Samba Web Administration Tool (SWAT). On the
Change Password field, it is possible to insert arbitrary content into
the user field (CVE-2011-2694).

Packages for 2009.0 are provided as of the Extended Maintenance
Program. Please visit this link to learn more:
http://store.mandriva.com/product_info.php?cPath=149 products_id=490

The updated packages have been patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2011-2522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2011-2694"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64netapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64netapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbclient0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64smbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64talloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64talloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64tdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64wbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbclient0-static-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbsharemodes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libsmbsharemodes0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtalloc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:mount-cifs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:nss_wins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2009.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:linux:2010.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64netapi-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64netapi0-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbclient0-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbclient0-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbclient0-static-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbsharemodes-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64smbsharemodes0-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64talloc-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64talloc1-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64tdb-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64tdb1-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64wbclient-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"x86_64", reference:"lib64wbclient0-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnetapi-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libnetapi0-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbclient0-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbclient0-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbclient0-static-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbsharemodes-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libsmbsharemodes0-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libtalloc-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libtalloc1-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libtdb-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libtdb1-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libwbclient-devel-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", cpu:"i386", reference:"libwbclient0-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"mount-cifs-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"nss_wins-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-client-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-common-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-doc-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-server-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-swat-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2009.0", reference:"samba-winbind-3.3.12-0.6mdv2009.0", yank:"mdv")) flag++;

if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64netapi-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64netapi0-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64smbclient0-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64smbclient0-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64smbclient0-static-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64smbsharemodes-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64smbsharemodes0-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64wbclient-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"x86_64", reference:"lib64wbclient0-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnetapi-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libnetapi0-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsmbclient0-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsmbclient0-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsmbclient0-static-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsmbsharemodes-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libsmbsharemodes0-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libwbclient-devel-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", cpu:"i386", reference:"libwbclient0-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"mount-cifs-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"nss_wins-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"samba-client-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"samba-common-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"samba-doc-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"samba-domainjoin-gui-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"samba-server-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"samba-swat-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;
if (rpm_check(release:"MDK2010.1", reference:"samba-winbind-3.5.3-3.3mdv2010.2", yank:"mdv")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
