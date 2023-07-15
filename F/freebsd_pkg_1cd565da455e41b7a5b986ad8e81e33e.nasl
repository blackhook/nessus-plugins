#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
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
  script_id(158217);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/22");

  script_name(english:"FreeBSD : seatd-launch -- remove files with escalated privileges with SUID (1cd565da-455e-41b7-a5b9-86ad8e81e33e)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The version of FreeBSD installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 1cd565da-455e-41b7-a5b9-86ad8e81e33e advisory.

  - Kenny Levinsen reports: seatd-launch could use a user-specified socket path instead of the
    internally generated socket path, and would unlink the socket path             before use to guard against
    collision with leftover sockets. This             meant that a caller could freely control what file path
    would be             unlinked and replaced with a user-owned seatd socket for the duration             of
    the session. If seatd-launch had the SUID bit set, this could be used by a             malicious user to
    remove files with the privileges of the owner of             seatd-launch, which is likely root, and
    replace it with a user-owned             domain socket. This does not directly allow retrieving the
    contents of existing             files, and the user-owned socket file is at the current time not
    believed to be directly useful for further exploitation. (1cd565da-455e-41b7-a5b9-86ad8e81e33e)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.sr.ht/~kennylevinsen/seatd-announce/%3CETEO7R.QG8B1KGD531R1%40kl.wtf%3E
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0de37a82");
  # https://vuxml.freebsd.org/freebsd/1cd565da-455e-41b7-a5b9-86ad8e81e33e.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?117527c6");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seatd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


var flag = 0;

var packages = [
    'seatd>=0.6.0<0.6.4'
];

foreach var package( packages ) {
    if (pkg_test(save_report:TRUE, pkg: package)) flag++;
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : pkg_report_get()
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
