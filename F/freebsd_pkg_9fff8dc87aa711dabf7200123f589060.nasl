#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2018 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21487);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2005-3352");
  script_bugtraq_id(15834);

  script_name(english:"FreeBSD : apache -- mod_imap XSS flaw (9fff8dc8-7aa7-11da-bf72-00123f589060)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Apache HTTP Server Project reports :

A flaw in mod_imap when using the Referer directive with image maps.
In certain site configurations a remote attacker could perform a
cross-site scripting attack if a victim can be forced to visit a
malicious URL using certain web browsers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apacheweek.com/features/security-13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.apacheweek.com/features/security-20"
  );
  # https://vuxml.freebsd.org/freebsd/9fff8dc8-7aa7-11da-bf72-00123f589060.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?518ae251"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_accel+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_deflate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+mod_ssl+mod_snmp+mod_deflate+ipv6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache+ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:apache_fp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ru-apache+mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"apache>=1.3<1.3.34_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache>=2.0.35<2.0.55_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache>=2.1<2.1.9_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache>=2.2<2.2.0_3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_perl<1.3.34_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache_fp>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+ipv6<1.3.37")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-apache<1.3.34+30.22_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ru-apache+mod_ssl<1.3.34+30.22+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+ssl>=1.3.0<1.3.33.1.55_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+ipv6<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+ipv6<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+mod_deflate<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_accel+mod_deflate+ipv6<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_deflate<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_deflate+ipv6<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel+ipv6<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_deflate<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_deflate+ipv6<1.3.34+2.8.25_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"apache+mod_ssl+mod_snmp+mod_accel+mod_deflate+ipv6<1.3.34+2.8.25_1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
