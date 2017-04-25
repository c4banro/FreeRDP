/**
* FreeRDP: A Remote Desktop Protocol Implementation
* Windows Desktop Sharing
*
* Copyright 2017 C4B COM For Business AG, Andreas Rossi <andreas.rossi@c4b.de>
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef FREERDP_WDS_H
#define FREERDP_WDS_H

#include <freerdp/api.h>
#include <freerdp/settings.h>


struct rdp_wds_connectionstring
{
	char* RASessionId;			// <A ID=
	char* RASpecificParams;		// <A KH=
	char* Sid;                  // <T SID=

	char* MachineAddress;
	UINT32 MachinePort;

	UINT32 MachineCount;
	char** MachineAddresses;
	UINT32* MachinePorts;
	};
typedef struct rdp_wds_connectionstring rdpWdsConnectionstring;


#ifdef __cplusplus
extern "C" {
#endif
	//<E><A KH="W111qeblP+fRNOpdtxweUCg6HJ8=" ID="AuthString"/><C><T ID="1" SID="0"><L P="51125" N="fe80::6cf0:c374:dffd:c82%12"/><L P="51126" N="172.16.1.118"/></T></C></E>

	FREERDP_API int freerdp_wds_connectionstring_parse_string( rdpWdsConnectionstring* connectionString, const char* string );
	FREERDP_API int freerdp_wds_connectionstring_parse_file( rdpWdsConnectionstring* connectionString, const char* filepath );

	FREERDP_API int freerdp_client_populate_settings_from_wds_connectionstring( rdpWdsConnectionstring* connectionString, rdpSettings* settings );

	FREERDP_API rdpWdsConnectionstring* freerdp_wds_connectionstring_new( void );
	FREERDP_API void freerdp_wds_connectionstring_free( rdpWdsConnectionstring* connectionString );

	FREERDP_API int freerdp_wds_connectionstring_write_to_file( rdpWdsConnectionstring* connectionString, const char* filepath );
	FREERDP_API int freerdp_wds_connectionstring_write_to_string( rdpWdsConnectionstring* connectionString, char* string, int stringSize );

#ifdef __cplusplus
}
#endif

typedef struct rdp_wds_reverseconnection rdpWdsReverseConnection;

FREERDP_LOCAL rdpWdsReverseConnection* freerdp_wds_reverse_connect_new();
FREERDP_LOCAL void freerdp_wds_reverse_connect_free( rdpWdsReverseConnection* connection );

FREERDP_LOCAL int freerdp_wds_prepare_reverse_connect( rdpWdsReverseConnection* connection );
FREERDP_LOCAL int freerdp_wds_connectionstring_fill_from_reverse_connection( rdpWdsConnectionstring* connectionString, const rdpWdsReverseConnection* connection );
FREERDP_LOCAL int freerdp_wds_wait_for_connect( rdpWdsReverseConnection* connection, HANDLE abortEvent );
FREERDP_LOCAL int freerdp_wds_update_settings_after_reverse_connect( rdpWdsReverseConnection* connection, rdpSettings* settings );


#endif