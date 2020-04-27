AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

gssincludedir = $(includedir)/gssapi

GSSSANON_EXPORTS = mech_sanon.exports

gssdir = $(libdir)/gss
gss_LTLIBRARIES = mech_sanon.la

mech_sanon_la_CFLAGS   = -Werror -Wall -Wunused-parameter @KRB5_CFLAGS@
mech_sanon_la_CPPFLAGS = -DGSSAPI_CALLCONV=KRB5_CALLCONV -DBUILD_GSSSANON_LIB -I$(srcdir)/x25519 -I$(srcdir)
mech_sanon_la_DEPENDENCIES = $(GSSSANON_EXPORTS)
mech_sanon_la_LDFLAGS  = -avoid-version -module -export-symbols $(GSSSANON_EXPORTS) -no-undefined @KRB5_LDFLAGS@
mech_sanon_la_LIBADD   = @KRB5_LIBS@ 

mech_sanon_la_SOURCES =    		\
	accept_sec_context.c		\
	acquire_cred.c			\
	add_cred.c			\
	canonicalize_name.c		\
	context_time.c			\
	crypto.c			\
	delete_sec_context.c		\
	derive.c			\
	display_name.c			\
	display_status.c		\
	duplicate_name.c		\
	export_name.c			\
	export_sec_context.c		\
	external.c			\
	import_cred.c			\
	import_name.c			\
	import_sec_context.c		\
	init_sec_context.c		\
	inquire_attrs_for_mech.c	\
	inquire_context.c		\
	inquire_cred.c			\
	inquire_cred_by_mech.c		\
	inquire_mechs_for_name.c	\
	inquire_names_for_mech.c	\
	inquire_sec_context_by_oid.c	\
	negoex.c			\
	process_context_token.c		\
	release_cred.c			\
	release_name.c			\
	release_oid.c			\
	rfc4121.c			\
	x25519/ed25519_ref10.c		\
	x25519/x25519_ref10.c