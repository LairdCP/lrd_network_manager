/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifndef NM_ACTIVATION_REQUEST_H
#define NM_ACTIVATION_REQUEST_H

#include <glib/gtypes.h>
#include <glib-object.h>
#include "nm-connection.h"
#include "nm-active-connection.h"

#define NM_TYPE_ACT_REQUEST            (nm_act_request_get_type ())
#define NM_ACT_REQUEST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACT_REQUEST, NMActRequest))
#define NM_ACT_REQUEST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACT_REQUEST, NMActRequestClass))
#define NM_IS_ACT_REQUEST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACT_REQUEST))
#define NM_IS_ACT_REQUEST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_ACT_REQUEST))
#define NM_ACT_REQUEST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACT_REQUEST, NMActRequestClass))

typedef struct {
	GObject parent;
} NMActRequest;

typedef enum {
	SECRETS_CALLER_NONE = 0,
	SECRETS_CALLER_ETHERNET,
	SECRETS_CALLER_WIFI,
	SECRETS_CALLER_GSM,
	SECRETS_CALLER_CDMA,
	SECRETS_CALLER_PPP,
	SECRETS_CALLER_HSO_GSM
} RequestSecretsCaller;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*connection_secrets_updated)  (NMActRequest *req,
	                                     NMConnection *connection,
	                                     GSList *updated_settings,
	                                     RequestSecretsCaller caller);
	void (*connection_secrets_failed)   (NMActRequest *req,
	                                     NMConnection *connection,
	                                     const char *setting,
	                                     RequestSecretsCaller caller);

	void (*properties_changed) (NMActRequest *req, GHashTable *properties);
} NMActRequestClass;

GType nm_act_request_get_type (void);

NMActRequest *nm_act_request_new          (NMConnection *connection,
                                           const char *specific_object,
                                           gboolean user_requested,
                                           gpointer *device);  /* An NMDevice */

NMConnection *nm_act_request_get_connection     (NMActRequest *req);
gboolean      nm_act_request_request_connection_secrets (NMActRequest *req,
                                                         const char *setting_name,
                                                         gboolean request_new,
                                                         RequestSecretsCaller caller,
                                                         const char *hint1,
                                                         const char *hint2);
const char *  nm_act_request_get_specific_object (NMActRequest *req);

void          nm_act_request_set_specific_object (NMActRequest *req,
                                                  const char *specific_object);

gboolean      nm_act_request_get_user_requested (NMActRequest *req);

const char *  nm_act_request_get_active_connection_path (NMActRequest *req);

void          nm_act_request_set_default (NMActRequest *req, gboolean is_default);

gboolean      nm_act_request_get_default (NMActRequest *req);

gboolean      nm_act_request_get_shared (NMActRequest *req);

void          nm_act_request_set_shared (NMActRequest *req, gboolean shared);

GObject *     nm_act_request_get_device (NMActRequest *req);

#endif /* NM_ACTIVATION_REQUEST_H */
