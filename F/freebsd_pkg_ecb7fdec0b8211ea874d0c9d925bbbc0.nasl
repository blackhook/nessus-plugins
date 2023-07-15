#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
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

include("compat.inc");

if (description)
{
  script_id(131173);
  script_version("1.5");
  script_cvs_date("Date: 2019/12/16");

  script_cve_id("CVE-2019-0154", "CVE-2019-11112");

  script_name(english:"FreeBSD : drm graphics drivers -- Local privilege escalation and denial of service (ecb7fdec-0b82-11ea-874d-0c9d925bbbc0)");
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
"Intel reports :

As part of IPU 2019.2, INTEL-SA-00242 advises that insufficient access
control may allow an authenticated user to potentially enable
escalation of privilege via local access.

INTEL-SA-00260 advises that insufficient access control may allow an
authenticated user to potentially enable denial of service via local
access."
  );
  # https://blogs.intel.com/technology/2019/11/ipas-november-2019-intel-platform-update-ipu
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d8cf984"
  );
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d063168b"
  );
  # https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf9021c3"
  );
  # https://vuxml.freebsd.org/freebsd/ecb7fdec-0b82-11ea-874d-0c9d925bbbc0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d25d4ab3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drm-current-kmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drm-devel-kmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drm-fbsd11.2-kmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:drm-fbsd12.0-kmod");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"drm-current-kmod<4.16.g20191120")) flag++;
if (pkg_test(save_report:TRUE, pkg:"drm-devel-kmod<5.0.g20191120")) flag++;
if (pkg_test(save_report:TRUE, pkg:"drm-fbsd12.0-kmod<4.16.g20191120")) flag++;
if (pkg_test(save_report:TRUE, pkg:"drm-fbsd11.2-kmod<4.11.g20191204")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
