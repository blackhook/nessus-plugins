#%NASL_MIN_LEVEL 999999

# @DEPRECATED@ 
# 
# This script has been deprecated by fedora_2006-028.nasl. 
# 
# Disabled on 2012/10/01. 
# 

#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from Fedora Security
# Advisory 2005-028.
#

include("compat.inc");

if (description)
{
  script_id(62250);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/20  0:18:52");

  script_cve_id("CVE-2005-3625", "CVE-2005-3626", "CVE-2005-3627");
  script_xref(name:"FEDORA", value:"2005-028");

  script_name(english:"Fedora Core 4 : tetex-3.0-9.FC4 (2005-028)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several flaws were discovered in the way teTeX processes PDF files. An
attacker could construct a carefully crafted PDF file that could cause
poppler to crash or possibly execute arbitrary code when opened.

The Common Vulnerabilities and Exposures project assigned the names
CVE-2005-3625, CVE-2005-3626, and CVE-2005-3627 to these issues.

This package also updates bindings in texdoc and causes the local
texmf tree to be searched first."
  );
  # http://lists.fedoraproject.org/pipermail/announce/2006-January/001740.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ab729f2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


# Deprecated.
exit(0, "This plugin has been deprecated. Refer to plugin #20409 (fedora_2006-028.nasl) instead.");

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC4", reference:"tetex-3.0-9.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-afm-3.0-9.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-debuginfo-3.0-9.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-doc-3.0-9.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-dvips-3.0-9.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-fonts-3.0-9.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-latex-3.0-9.FC4")) flag++;
if (rpm_check(release:"FC4", reference:"tetex-xdvi-3.0-9.FC4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
