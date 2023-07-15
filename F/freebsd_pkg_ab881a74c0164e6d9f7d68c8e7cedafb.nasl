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
  script_id(103909);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-10971", "CVE-2017-10972");

  script_name(english:"FreeBSD : xorg-server -- Multiple Issues (ab881a74-c016-4e6d-9f7d-68c8e7cedafb)");
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
"xorg-server developers reports :

In the X.Org X server before 2017-06-19, a user authenticated to an X
Session could crash or execute code in the context of the X Server by
exploiting a stack overflow in the endianness conversion of X Events.

Uninitialized data in endianness conversion in the XEvent handling of
the X.Org X Server before 2017-06-19 allowed authenticated malicious
users to access potentially privileged data from the X server."
  );
  # http://www.securityfocus.com/bid/99546
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/99546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035283"
  );
  # https://cgit.freedesktop.org/xorg/xserver/commit/?id=215f894965df5fb0bb45b107d84524e700d2073c
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca9626a5"
  );
  # https://cgit.freedesktop.org/xorg/xserver/commit/?id=8caed4df36b1f802b4992edcfd282cbeeec35d9d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c59234c4"
  );
  # https://cgit.freedesktop.org/xorg/xserver/commit/?id=ba336b24052122b136486961c82deac76bbde455
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34c7477b"
  );
  # http://www.securityfocus.com/bid/99543
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.securityfocus.com/bid/99543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035283"
  );
  # https://cgit.freedesktop.org/xorg/xserver/commit/?id=05442de962d3dc624f79fc1a00eca3ffc5489ced
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2e446704"
  );
  # https://vuxml.freebsd.org/freebsd/ab881a74-c016-4e6d-9f7d-68c8e7cedafb.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5460b1bf"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:xorg-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"xorg-server<=1.18.4_6,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"xorg-server>=1.19.0,1<=1.19.3,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
