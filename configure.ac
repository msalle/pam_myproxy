#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.57])
AC_INIT([pam_myproxy], [0.1.0], [msalle@nikhef.nl])
AM_INIT_AUTOMAKE([1.6.3 foreign])
# Don't build static libs
LT_INIT([disable-static])

AC_COPYRIGHT([Copyright (c) 2012 Nikhef.
See LICENCE file for details
])

# Allow custom location for the config file
AC_ARG_WITH([config],
    [AC_HELP_STRING([--with-config=FILE],
        [use specified FILE as config [default=SYSCONFDIR/pam_myproxy.conf]])],
    [AS_IF([test "x$withval" = "xyes" -o "x$withval" = "xno" ],
        [AC_MSG_FAILURE([Option --with-config needs a filename])],
        [AS_IF([test "x`echo $withval|cut -c1`" != "x/" ],
            [AC_MSG_FAILURE([Option --with-config needs an absolute filename])],
            [AS_IF([test "x`echo "$withval"|grep '\.\.'`" != "x" ],
                [AC_MSG_FAILURE([Option --with-config may not contain '..'])],
                [CONFIG_FILE=$withval])
            ])
        ])
    ],
    [CONFIG_FILE=$sysconfdir/pam_myproxy.conf])

# Print and subsitute the result.
AC_MSG_RESULT([CONFIG_FILE set to $CONFIG_FILE])
AC_SUBST(CONFIG_FILE)

AC_PROG_CC
AC_PROG_LIBTOOL

AC_CHECK_LIB([crypto], [X509_free])
AC_CHECK_LIB([ssl], [SSL_CTX_free])

AC_CHECK_HEADERS([openssl/ssl.h openssl/err.h openssl/x509v3.h openssl/bio.h security/pam_modules.h])

AC_CONFIG_FILES([Makefile])
AC_CONFIG_HEADERS([pam_myproxy_config.h])

AC_OUTPUT
