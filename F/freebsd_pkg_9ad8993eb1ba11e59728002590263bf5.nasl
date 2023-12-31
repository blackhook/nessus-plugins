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
  script_id(87700);
  script_version("2.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2015-8567", "CVE-2015-8568");

  script_name(english:"FreeBSD : qemu -- denial of service vulnerability in VMWARE VMXNET3 NIC support (9ad8993e-b1ba-11e5-9728-002590263bf5)");
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
"Prasad J Pandit, Red Hat Product Security Team, reports :

Qemu emulator built with a VMWARE VMXNET3 paravirtual NIC emulator
support is vulnerable to a memory leakage flaw. It occurs when a guest
repeatedly tries to activate the vmxnet3 device.

A privileged guest user could use this flaw to leak host memory,
resulting in DoS on the host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=205813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=205814"
  );
  # http://www.openwall.com/lists/oss-security/2015/12/15/4
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openwall.com/lists/oss-security/2015/12/15/4"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.gnu.org/archive/html/qemu-devel/2015-12/msg02299.html"
  );
  # http://git.qemu.org/?p=qemu.git;a=commit;h=aa4a3dce1c88ed51b616806b8214b7c8428b7470
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?287c6345"
  );
  # https://github.com/seanbruno/qemu-bsd-user/commit/aa4a3dce1c88ed51b616806b8214b7c8428b7470
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5818fd73"
  );
  # https://vuxml.freebsd.org/freebsd/9ad8993e-b1ba-11e5-9728-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5aa7907d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-sbruno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:qemu-user-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"qemu<2.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-devel<2.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-sbruno<2.5.50.g20160213")) flag++;
if (pkg_test(save_report:TRUE, pkg:"qemu-user-static<2.5.50.g20160213")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
