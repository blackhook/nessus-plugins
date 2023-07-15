#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2020 Jacques Vidrine and contributors
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
  script_id(137870);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/10");

  script_cve_id("CVE-2020-14002");

  script_name(english:"FreeBSD : PuTTY -- Release 0.74 fixes two security vulnerabilities (6190c0cd-b945-11ea-9401-2dcf562daa69)");
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
"Simon Tatham reports :

[Release 0.74] fixes the following security issues :

- New configuration option to disable PuTTY's default policy of
changing its host key algorithm preferences to prefer keys it already
knows. (There is a theoretical information leak in this policy.)
[CVE-2020-14002]

- In some situations an SSH server could cause PuTTY to access freed
mdmory by pretending to accept an SSH key and then refusing the actual
signature. It can only happen if you're using an SSH agent."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.tartarus.org/pipermail/putty-announce/2020/000030.html"
  );
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-dynamic-hostkey-info-leak.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50869cce"
  );
  # https://www.fzi.de/en/news/news/detail-en/artikel/fsa-2020-2-ausnutzung-eines-informationslecks-fuer-gezielte-mitm-angriffe-auf-ssh-clients/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfb73fdc"
  );
  # https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-agent-keylist-used-after-free.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de7afab5"
  );
  # https://vuxml.freebsd.org/freebsd/6190c0cd-b945-11ea-9401-2dcf562daa69.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f31b30c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty-nogtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if (pkg_test(save_report:TRUE, pkg:"putty<0.74")) flag++;
if (pkg_test(save_report:TRUE, pkg:"putty-gtk2<0.74")) flag++;
if (pkg_test(save_report:TRUE, pkg:"putty-nogtk<0.74")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
