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
  script_id(34045);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2008-4195", "CVE-2008-4197", "CVE-2008-4198", "CVE-2008-4200");

  script_name(english:"FreeBSD : opera -- multiple vulnerabilities (73ec1008-72f0-11dd-874b-0030843d3802)");
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
"The Opera Team reports :

Scripts are able to change the addresses of framed pages that come
from the same site. Due to a flaw in the way that Opera checks what
frames can be changed, a site can change the address of frames on
other sites inside any window that it has opened. This allows sites to
open pages from other sites, and display misleading information on
them.

Custom shortcut and menu commands can be used to activate external
applications. In some cases, the parameters passed to these
applications are not prepared correctly, and may be created from
uninitialized memory. These may be misinterpreted as additional
parameters, and depending on the application, this could allow
execution of arbitrary code.

Successful exploitation requires convincing the user to modify their
shortcuts or menu files appropriately, pointing to an appropriate
target application, then to activate that shortcut at an appropriate
time. To inject code, additional means will have to be employed.

When insecure pages load content from secure sites into a frame, they
can cause Opera to incorrectly report the insecure site as being
secure. The padlock icon will incorrectly be shown, and the security
information dialog will state that the connection is secure, but
without any certificate information.

As a security precaution, Opera does not allow Web pages to link to
files on the user's local disk. However, a flaw exists that allows Web
pages to link to feed source files on the user's computer. Suitable
detection of JavaScript events and appropriate manipulation can
unreliably allow a script to detect the difference between successful
and unsuccessful subscriptions to these files, to allow it to discover
if the file exists or not. In most cases the attempt will fail.

It has been reported that when a user subscribes to a news feed using
the feed subscription button, the page address can be changed. This
causes the address field not to update correctly. Although this can
mean that misleading information can be displayed in the address
field, it can only leave the attacking page's address in the address
bar, not a trusted third party address."
  );
  # http://www.opera.com/support/search/view/893/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8336a0c"
  );
  # http://www.opera.com/support/search/view/894/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e0079f32"
  );
  # http://www.opera.com/support/search/view/895/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1661fda"
  );
  # http://www.opera.com/support/search/view/896/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?051446dc"
  );
  # http://www.opera.com/support/search/view/897/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e87f8b54"
  );
  # https://vuxml.freebsd.org/freebsd/73ec1008-72f0-11dd-874b-0030843d3802.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07e7a878"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-opera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:opera");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"opera<9.52")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-opera<9.52")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
