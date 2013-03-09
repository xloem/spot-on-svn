#include <stdio.h>
#include <stdlib.h>
#include "libspoton.h"

int main(void)
{
  libspoton_error_t rc = LIBSPOTON_ERROR_NONE;
  libspoton_handle_t libspotonHandle;

  if((rc = libspoton_init("shared.db",
			  &libspotonHandle)) != LIBSPOTON_ERROR_NONE)
    printf("libspoton_init() error (%s).\n", libspoton_strerror(rc));

  if((rc = libspoton_register_kernel(100,
				     false,
				     &libspotonHandle)) !=
     LIBSPOTON_ERROR_NONE)
    printf("libspoton_register_kernel() error (%s).\n",
	   libspoton_strerror(rc));

  if((rc = libspoton_generate_private_public_keys("0123456789",
						  "aes256",
						  1024,
						  &libspotonHandle)) !=
     LIBSPOTON_ERROR_NONE)
    printf("libspoton_generate_private_public_keys() error (%s).\n",
	   libspoton_strerror(rc));

  libspoton_close(&libspotonHandle);

  if((rc = libspoton_init("shared.db", &libspotonHandle)) !=
     LIBSPOTON_ERROR_NONE)
    printf("libspoton_init() error (%s).\n", libspoton_strerror(rc));

  if((rc = libspoton_populate_public_key(&libspotonHandle)) !=
     LIBSPOTON_ERROR_NONE)
    printf("libspoton_populate_public_key() error (%s).\n",
	   libspoton_strerror(rc));

  const char *description = "Dooble";
  const char *title = "Dooble Web Browser";
  const char *url = "http://dooble.sourceforge.net";

  if((rc = libspoton_save_url(url,
			      strlen(url),
			      title,
			      strlen(title),
			      description,
			      strlen(description),
			      &libspotonHandle)) !=
     LIBSPOTON_ERROR_NONE)
    printf("libspoton_save_url() error (%s).\n",
	   libspoton_strerror(rc));

  url = "http://spot-on.sourceforge.net";

  if((rc = libspoton_save_url(url,
			      strlen(url),
			      "",
			      0,
			      0,
			      0,
			      &libspotonHandle)) !=
     LIBSPOTON_ERROR_NONE)
    printf("libspoton_save_url() error (%s).\n",
	   libspoton_strerror(rc));

  if((rc = libspoton_deregister_kernel(100, &libspotonHandle)) !=
     LIBSPOTON_ERROR_NONE)
    printf("libspoton_deregister_kernel() error (%s).\n",
	   libspoton_strerror(rc));

  libspoton_close(&libspotonHandle);
  return EXIT_SUCCESS;
}
