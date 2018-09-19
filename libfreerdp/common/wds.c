/**
* FreeRDP: A Remote Desktop Protocol Implementation
* Windows Desktop Sharing
*
* Copyright 2018 C4B COM For Business AG, Andreas Rossi <andreas.rossi@c4b.de>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#include <winpr/crt.h>
#include <winpr/crypto.h>
#include <winpr/print.h>
#include <winpr/windows.h>
#include <winpr/handle.h>
#include <winpr/synch.h>
#include <winpr/winsock.h>

#include <freerdp/log.h>
#include <freerdp/client/file.h>
#include <freerdp/client/cmdline.h>

#include <freerdp/wds.h>


#define TAG FREERDP_TAG("core")



FREERDP_API int freerdp_wds_connectionstring_fill( rdpWdsConnectionstring* connectionString, const char* raSpecificParameters, const char* raSessionId, const char* sid, UINT32 machineCount, char** machines, UINT32* ports )
{
	if ( raSpecificParameters )
	{
		if ( connectionString->RASpecificParams )
			free( connectionString->RASpecificParams );
		connectionString->RASpecificParams = _strdup( raSpecificParameters );
		if ( !connectionString->RASpecificParams )
			return -1;
	}

	if ( raSessionId )
	{
		if ( connectionString->RASessionId )
			free( connectionString->RASessionId );
		connectionString->RASessionId = _strdup( raSessionId );
		if ( !connectionString->RASessionId )
			return -1;
	}

	if ( sid )
	{
		if ( connectionString->Sid )
			free( connectionString->Sid );
		connectionString->Sid = _strdup( sid );
		if ( !connectionString->Sid )
			return -1;
	}

	if ( machineCount <= 0 || !machines || !ports )
		return 1;

	UINT32 count = 0;
	if ( connectionString->MachineAddresses )
	{
		while ( count <= connectionString->MachineCount )
		{
			if ( connectionString->MachineAddresses[count] )
				free( connectionString->MachineAddresses[count] );
			count++;
		}
		free( connectionString->MachineAddresses );
	}
	if ( connectionString->MachinePorts )
		free( connectionString->MachinePorts );

	connectionString->MachineAddresses = (char**)calloc( machineCount, sizeof( char* ) );
	connectionString->MachinePorts = (UINT32*)calloc( machineCount, sizeof( UINT32 ) );

	if ( !connectionString->MachineAddresses || !connectionString->MachinePorts )
		return -1;

	count = 0;
	while ( count < machineCount )
	{
		connectionString->MachineAddresses[count] = _strdup( machines[count] );
		if ( !connectionString->MachineAddresses[count] )
			return -1;
		connectionString->MachinePorts[count] = ports[count];
		count++;
	}
	connectionString->MachineCount = machineCount;

	if ( connectionString->MachineAddress )
		free( connectionString->MachineAddress );
	connectionString->MachineAddress = _strdup( machines[machineCount - 1] );
	if ( !connectionString->MachineAddress )
		return -1;
	connectionString->MachinePort = ports[machineCount - 1];
	return 1;
}

// <E>
//		<A KH="W111qeblP+fRNOpdtxweUCg6HJ8=" ID="AuthString" />
//		<C>
//			<T ID="1" SID="0">
//				<L P="51125" N="fe80::6cf0:c374:dffd:c82%12" />
//				<L P="51126" N="172.16.1.118" />
//			</T>
//		</C>
// </E>
FREERDP_API int freerdp_wds_connectionstring_parse_string( rdpWdsConnectionstring* connectionString, const char* string )
{
	char* str;
	char* tag;
	char* end;
	char* p;
	int ret = -1;


	str = (char*)string;

	if ( !strstr( str, "<E>" ) )
		return -1;

	if ( !strstr( str, "<C>" ) )
		return -1;

	str = _strdup( string );
	if ( !str )
		return -1;

	if ( !(tag = strstr( str, "<A" )) )
		goto out_fail;

	/* Parse Auth String Node (<A>) */
	end = strstr( tag, "/>" );
	if ( !end )
		goto out_fail;

	*end = '\0';

	p = strstr( tag, "KH=\"" );
	if ( p )
	{
		char *q;
		size_t length;
		p += sizeof( "KH=\"" ) - 1;
		q = strchr( p, '"' );

		if ( !q )
			goto out_fail;

		length = q - p;
		free( connectionString->RASpecificParams );
		connectionString->RASpecificParams = (char*)malloc( length + 1 );
		if ( !connectionString->RASpecificParams )
			goto out_fail;

		CopyMemory( connectionString->RASpecificParams, p, length );
		connectionString->RASpecificParams[length] = '\0';
	}

	p = strstr( tag, "ID=\"" );
	if ( p )
	{
		char *q;
		size_t length;
		p += sizeof( "ID=\"" ) - 1;
		q = strchr( p, '"' );

		if ( !q )
			goto out_fail;

		length = q - p;
		free( connectionString->RASessionId );
		connectionString->RASessionId = (char*)malloc( length + 1 );
		if ( !connectionString->RASessionId )
			goto out_fail;

		CopyMemory( connectionString->RASessionId, p, length );
		connectionString->RASessionId[length] = '\0';
	}
	*end = '/';

	/* Parse <T */
	if ( !(tag = strstr( str, "<T" )) )
		goto out_fail;

	end = strstr( tag, ">" );
	if ( !end )
		goto out_fail;

	*end = '\0';
	p = strstr( tag, "SID=\"" );
	if ( p )
	{
		char *q;
		size_t length;
		p += sizeof( "SID=\"" ) - 1;
		q = strchr( p, '"' );

		if ( !q )
			goto out_fail;
		length = q - p;
		free( connectionString->Sid );
		connectionString->Sid = (char*)malloc( length + 1 );
		if ( !connectionString->Sid )
			goto out_fail;

		CopyMemory( connectionString->Sid, p, length );
		connectionString->Sid[length] = '\0';
	}
	*end = '>';

	/* Count <L - nodes*/
	int lNodeCount = 0;
	p = strstr( str, "<L P=\"" );
	while ( p )
	{
		lNodeCount++;
		p++;
		p = strstr( p, "<L P=\"" );
	}

	if ( 0 == lNodeCount )
		goto out_fail;

	connectionString->MachineCount = lNodeCount;
	connectionString->MachineAddresses = (char**)calloc( lNodeCount, sizeof( char* ) );
	connectionString->MachinePorts = (UINT32*)calloc( lNodeCount, sizeof( UINT32 ) );

	if ( !connectionString->MachineAddresses || !connectionString->MachinePorts )
		goto out_fail;


	/* Parse <L  - nodes */
	lNodeCount = 0;
	p = strstr( str, "<L P=\"" );
	while ( p )
	{
		char *q;
		int port;
		size_t length;
		p += sizeof( "<L P=\"" ) - 1;

		q = strchr( p, '"' );

		if ( !q )
			goto out_fail;

		q[0] = '\0';
		q++;

		port = (UINT32)atoll( p );

		p = strstr( q, " N=\"" );

		if ( !p )
			goto out_fail;

		p += sizeof( " N=\"" ) - 1;

		q = strchr( p, '"' );

		if ( !q )
			goto out_fail;

		q[0] = '\0';
		q++;

		char* r = strrchr( p, '%' );
		if ( r )
			r[0] = '\0';

		length = strlen( p );

		if ( connectionString->MachineAddresses[lNodeCount] )
			free( connectionString->MachineAddresses[lNodeCount] );
		connectionString->MachineAddresses[lNodeCount] = _strdup( p );
		if ( !connectionString->MachineAddresses[lNodeCount] )
			goto out_fail;
		connectionString->MachinePorts[lNodeCount] = (UINT32)port;
		lNodeCount++;
		p = strstr( q, "<L P=\"" );
	}

	if ( connectionString->MachineAddress )
		free( connectionString->MachineAddress );
	connectionString->MachineAddress = _strdup( connectionString->MachineAddresses[lNodeCount - 1] );
	if ( !connectionString->MachineAddress )
		goto out_fail;
	connectionString->MachinePort = connectionString->MachinePorts[lNodeCount - 1];

	ret = 1;
out_fail:
	free( str );
	return ret;
}

FREERDP_API int freerdp_wds_connectionstring_parse_file( rdpWdsConnectionstring* connectionString, const char* filepath )
{
	int status;
	BYTE* buffer;
	FILE* fp = NULL;
	size_t readSize;
	long int fileSize;

	fp = fopen( filepath, "r" );

	if ( !fp )
		return -1;

	fseek( fp, 0, SEEK_END );
	fileSize = ftell( fp );
	fseek( fp, 0, SEEK_SET );

	if ( fileSize < 1 )
	{
		fclose( fp );
		return -1;
	}

	buffer = (BYTE*)malloc( fileSize + 2 );

	if ( !buffer )
	{
		fclose( fp );
		return -1;
	}

	readSize = fread( buffer, fileSize, 1, fp );

	if ( !readSize )
	{
		if ( !ferror( fp ) )
			readSize = fileSize;
	}
	fclose( fp );

	if ( readSize < 1 )
	{
		free( buffer );
		buffer = NULL;
		return -1;
	}

	buffer[fileSize] = '\0';
	buffer[fileSize + 1] = '\0';

	status = freerdp_wds_connectionstring_parse_string( connectionString, (char*)buffer );

	free( buffer );

	return status;
}

FREERDP_API int freerdp_client_populate_settings_from_wds_connectionstring( rdpWdsConnectionstring* connectionString, rdpSettings* settings )
{
	UINT32 i;

	if ( !connectionString->RASessionId || !connectionString->MachineAddress )
		return -1;

	freerdp_set_param_bool( settings, FreeRDP_RemoteAssistanceMode, TRUE );
	freerdp_set_param_string( settings, FreeRDP_RemoteAssistanceSessionId, connectionString->RASessionId );
	freerdp_set_param_string( settings, FreeRDP_Domain, "*" );

	//freerdp_set_param_string( settings, FreeRDP_Username, "MFCViewer" );
	//freerdp_set_param_string( settings, FreeRDP_RemoteAssistancePassword, "Password" );
	freerdp_set_param_bool( settings, FreeRDP_AutoLogonEnabled, TRUE );

	if ( connectionString->Sid && (0 != strcmp( connectionString->Sid, "0" )) )
	{
		freerdp_set_param_bool( settings, FreeRDP_SendPreconnectionPdu, TRUE );
		freerdp_set_param_uint32( settings, FreeRDP_PreconnectionId, (UINT32)atoll( connectionString->Sid ) );
	}

	if ( freerdp_set_param_string( settings, FreeRDP_ServerHostname, connectionString->MachineAddress ) != 0 )
		return -1;
	freerdp_set_param_uint32( settings, FreeRDP_ServerPort, connectionString->MachinePort );

	freerdp_target_net_addresses_free( settings );
	settings->TargetNetAddressCount = connectionString->MachineCount;
	if ( settings->TargetNetAddressCount )
	{
		settings->TargetNetAddresses = (char**)calloc( connectionString->MachineCount, sizeof( char* ) );
		settings->TargetNetPorts = (UINT32*)calloc( connectionString->MachineCount, sizeof( UINT32 ) );

		if ( !settings->TargetNetAddresses || !settings->TargetNetPorts )
			return -1;

		for ( i = 0; i < settings->TargetNetAddressCount; i++ )
		{
			settings->TargetNetAddresses[i] = _strdup( connectionString->MachineAddresses[i] );
			settings->TargetNetPorts[i] = connectionString->MachinePorts[i];

			if ( !settings->TargetNetAddresses[i] )
				return -1;
		}
	}

	freerdp_set_param_bool( settings, FreeRDP_RdpSecurity, TRUE );
	freerdp_set_param_bool( settings, FreeRDP_TlsSecurity, FALSE );
	freerdp_set_param_bool( settings, FreeRDP_NlaSecurity, FALSE );
	freerdp_set_param_bool( settings, FreeRDP_ExtSecurity, FALSE );
	return 1;
}

FREERDP_API rdpWdsConnectionstring* freerdp_wds_connectionstring_new( void )
{
	return (rdpWdsConnectionstring*)calloc( 1, sizeof( rdpWdsConnectionstring ) );
}

FREERDP_API void freerdp_wds_connectionstring_free( rdpWdsConnectionstring* connectionString )
{
	UINT32 i;

	if ( !connectionString )
		return;

	free( connectionString->RASessionId );
	free( connectionString->RASpecificParams );
	free( connectionString->Sid );
	free( connectionString->MachineAddress );

	for ( i = 0; i < connectionString->MachineCount; i++ )
	{
		free( connectionString->MachineAddresses[i] );
	}

	free( connectionString->MachineAddresses );
	free( connectionString->MachinePorts );
	free( connectionString );
}

FREERDP_API int freerdp_wds_connectionstring_write_to_file( rdpWdsConnectionstring* connectionString, const char* filepath )
{
	int length;
	char* str;

	length = freerdp_wds_connectionstring_write_to_string( connectionString, NULL, 0 );
	if ( length <= 0 )
		return -1;

	str = malloc( length + 1 );
	if ( freerdp_wds_connectionstring_write_to_string( connectionString, str, length + 1 ) < 0 )
		return -1;


	FILE* fp = NULL;

	fp = fopen( filepath, "w" );

	if ( !fp )
	{
		free( str );
		return -1;
	}

	if ( (int)fwrite( str, 1, length, fp ) < length )
	{
		free( str );
		return -1;
	}

	fclose( fp );
	free( str );
	return length;
}


int add_and_resize_if_needed( char** ppAct, int* pActLen, const char* add, int increment )
{
	if ( (int)(strlen( *ppAct ) + strlen( add )) < *pActLen )
	{
		strcat( *ppAct, add );
		return strlen( *ppAct );
	}

	int newSize = *pActLen + ((int)strlen( add ) / increment + 1) * increment;
	char* pNew = realloc( *ppAct, newSize );
	if ( !pNew )
		return -1;

	*ppAct = pNew;
	*pActLen = newSize;

	strcat( *ppAct, add );
	return strlen( *ppAct );
}

int add_and_resize_if_needed_uint( char** ppAct, int* pActLen, UINT32 add, int increment )
{
	char buffer[100];
	sprintf_s( buffer, 100, "%d", add );
	int ret = add_and_resize_if_needed( ppAct, pActLen, buffer, increment );
	return ret;
}

// <E>
//		<A KH="W111qeblP+fRNOpdtxweUCg6HJ8=" ID="AuthString" />
//		<C>
//			<T ID="1" SID="0">
//				<L P="51125" N="fe80::6cf0:c374:dffd:c82%12" />
//				<L P="51126" N="172.16.1.118" />
//			</T>
//		</C>
// </E>
FREERDP_API int freerdp_wds_connectionstring_write_to_string( rdpWdsConnectionstring* connectionString, char* string, int stringSize )
{
	int memLength = 1000;
	char* str = (char*)malloc( memLength );
	if ( !str )
		return -1;
	str[0] = '\0';
	
	if ( add_and_resize_if_needed( &str, &memLength, "<E>", 1000 ) < 0 )
		return -1;
	if ( !connectionString->RASessionId && !connectionString->RASpecificParams )
	{
		if ( add_and_resize_if_needed( &str, &memLength, "<A/>", 1000 ) < 0 )
			return -1;
	}
	else
	{
		if ( add_and_resize_if_needed( &str, &memLength, "<A ", 1000 ) < 0 )
			return -1;
		if ( connectionString->RASpecificParams )
		{
			if ( add_and_resize_if_needed( &str, &memLength, "KH=\"", 1000 ) < 0 )
				return -1;
			if ( add_and_resize_if_needed( &str, &memLength, connectionString->RASpecificParams, 1000 ) < 0 )
				return -1;
			if ( add_and_resize_if_needed( &str, &memLength, "\"", 1000 ) < 0 )
				return -1;
		}
		if ( connectionString->RASpecificParams && connectionString->RASessionId )
		{
			if ( add_and_resize_if_needed( &str, &memLength, " ", 1000 ) < 0 )
				return -1;
		}
		if ( connectionString->RASessionId )
		{
			if ( add_and_resize_if_needed( &str, &memLength, "ID=\"", 1000 ) < 0 )
				return -1;
			if ( add_and_resize_if_needed( &str, &memLength, connectionString->RASessionId, 1000 ) < 0 )
				return -1;
			if ( add_and_resize_if_needed( &str, &memLength, "\"", 1000 ) < 0 )
				return -1;
		}
		if ( add_and_resize_if_needed( &str, &memLength, "/>", 1000 ) < 0 )
			return -1;
	}

	if ( add_and_resize_if_needed( &str, &memLength, "<C><T ID=\"1\" ", 1000 ) < 0 )
		return -1;
	if ( !connectionString->Sid )
	{
		if ( add_and_resize_if_needed( &str, &memLength, "SID=\"0\">", 1000 ) < 0 )
			return -1;
	}
	else
	{
		if ( add_and_resize_if_needed( &str, &memLength, "SID=\"", 1000 ) < 0 )
			return -1;
		if ( add_and_resize_if_needed( &str, &memLength, connectionString->Sid, 1000 ) < 0 )
			return -1;
		if ( add_and_resize_if_needed( &str, &memLength, "\">", 1000 ) < 0 )
			return -1;
	}

	if ( connectionString->MachineCount > 0 && connectionString->MachineAddresses && connectionString->MachinePorts )
	{
		for ( UINT32 count = 0; count < connectionString->MachineCount; count++ )
		{
			if ( add_and_resize_if_needed( &str, &memLength, "<L P=\"", 1000 ) < 0 )
				return -1;
			if ( add_and_resize_if_needed_uint( &str, &memLength, connectionString->MachinePorts[count], 1000 ) < 0 )
				return -1;
			if ( add_and_resize_if_needed( &str, &memLength, "\" N=\"", 1000 ) < 0 )
				return -1;
			if ( add_and_resize_if_needed( &str, &memLength, connectionString->MachineAddresses[count], 1000 ) < 0 )
				return -1;
			if ( add_and_resize_if_needed( &str, &memLength, "\"/>", 1000 ) < 0 )
				return -1;
		}
	}

	if ( add_and_resize_if_needed( &str, &memLength, "</T></C></E>", 1000 ) < 0 )
		return -1;

	int length = strlen( str );

	if ( !string )
		return length;

	if ( length + 1 > stringSize )
		return -1;

	strcpy( string, str );
	return length;
}

typedef struct
{
	BOOL valid;
	SOCKET socket;
	char* address;
	int port;
	WSAEVENT event;
} Listener;

typedef struct
{
	SOCKET clientSocket;
	int nbListeners;
	Listener* Listeners;
    HANDLE* listenerDisconnectThread;
} ReverseConnection;

static void freerdp_wds_listener_disconnect( ReverseConnection* ctn );
static void* freerdp_listener_disconnect_thread( void* arg );

FREERDP_LOCAL rdpWdsReverseConnection* freerdp_wds_reverse_connect_new()
{
	ReverseConnection* newC = calloc( 1, sizeof( ReverseConnection ) );
	newC->clientSocket = INVALID_SOCKET;
    newC->Listeners = NULL;
    newC->nbListeners = 0;
    newC->listenerDisconnectThread = NULL;
	return (rdpWdsReverseConnection*)newC;
}

FREERDP_LOCAL void freerdp_wds_reverse_connect_free( rdpWdsReverseConnection* connection )
{
	if ( !connection )
		return;

	ReverseConnection* ctn = (ReverseConnection*)connection;

    WLog_INFO( TAG, "freerdp_wds_reverse_connect_free started" );

	if ( ctn->clientSocket != INVALID_SOCKET )
		closesocket( ctn->clientSocket );

    if ( ctn->listenerDisconnectThread != NULL )
    {
        WaitForSingleObject( ctn->listenerDisconnectThread, INFINITE );
        CloseHandle( ctn->listenerDisconnectThread );
    }

    freerdp_wds_listener_disconnect( ctn );
	free( ctn );

    WLog_INFO( TAG, "freerdp_wds_reverse_connect_free finished" );
}


FREERDP_LOCAL int freerdp_wds_prepare_reverse_connect( rdpWdsReverseConnection* connection )
{
	ReverseConnection* ctn = (ReverseConnection*)connection;
	if ( !ctn )
		return -1;

	int status;
	SOCKET sockfd;
	char addr[64];
    char tcpAddress[64];
	int option_value;
    LINGER linger;
	struct addrinfo* ai;
	struct addrinfo* res;
	struct addrinfo hints = { 0 };
	WSAEVENT socketEvent;

#ifdef _WIN32
	u_long arg;
#endif

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_flags = AI_PASSIVE;

	status = getaddrinfo( "", NULL, &hints, &res );
	if ( status != 0 )
		return -1;

	int nbAdresses = 0;
	for ( ai = res; ai; ai = ai->ai_next )
	{
		if ( (ai->ai_family != AF_INET) && (ai->ai_family != AF_INET6) )
			continue;

		nbAdresses++;
	}

    if ( !nbAdresses )
    {
        WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - don't find any tcp addresses" );
        return -1;
    }

    WLog_INFO( TAG, "freerdp_wds_prepare_reverse_connect - found %i ip addresses", nbAdresses );

	ctn->nbListeners = 0;
	ctn->Listeners = calloc( nbAdresses, sizeof( Listener ) );

	for ( ai = res; ai; ai = ai->ai_next )
	{
        if ( (ai->ai_family != AF_INET) && (ai->ai_family != AF_INET6) )
            continue;

        Listener* pListener = ctn->Listeners + ctn->nbListeners;

        tcpAddress[0] = 0;
        if ( ai->ai_family == AF_INET )
            inet_ntop( ai->ai_addr->sa_family, &(((struct sockaddr_in *)ai->ai_addr)->sin_addr), tcpAddress, sizeof( tcpAddress ) );
        else
            inet_ntop( ai->ai_addr->sa_family, &(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr), tcpAddress, sizeof( tcpAddress ) );
        WLog_INFO( TAG, "freerdp_wds_prepare_reverse_connect - try listen on %s", tcpAddress );

        pListener->valid = FALSE;

		sockfd = socket( ai->ai_family, ai->ai_socktype, ai->ai_protocol );
        if ( sockfd == INVALID_SOCKET )
        {
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i can't create socket for %s", WSAGetLastError(), tcpAddress );
            continue;
        }

		option_value = 1;
        if ( setsockopt( sockfd, SOL_SOCKET, SO_REUSEADDR, (void*)&option_value, sizeof( option_value ) ) )
        {
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in setsockopt SO_REUSEADDR for %s", WSAGetLastError(), tcpAddress );
            closesocket( (SOCKET)sockfd );
            continue;
        }

        linger.l_onoff = 1;
        linger.l_linger = 0;
        if ( setsockopt( sockfd, SOL_SOCKET, SO_LINGER, (void*)&linger, sizeof( linger ) ) )
        {
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in setsockopt SO_LINGER for %s", WSAGetLastError(), tcpAddress );
            closesocket( (SOCKET)sockfd );
            continue;
        }

#ifndef _WIN32
		fcntl( sockfd, F_SETFL, O_NONBLOCK );
#else
		arg = 1;
        if ( ioctlsocket( sockfd, FIONBIO, &arg ) )
        {
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in ioctlsocket for %s", WSAGetLastError(), tcpAddress );
            closesocket( (SOCKET)sockfd );
            continue;
        }
#endif

        socketEvent = WSACreateEvent();
        if ( WSA_INVALID_EVENT == socketEvent )
        {
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in WSACreateEvent for %s", WSAGetLastError(), tcpAddress );
            free( pListener->address );
            closesocket( (SOCKET)sockfd );
            continue;
        }
        if ( WSAEventSelect( sockfd, socketEvent, FD_ACCEPT ) )
        {
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in WSAEventSelect for %s", WSAGetLastError(), tcpAddress );
            closesocket( (SOCKET)sockfd );
            WSACloseEvent( socketEvent );
            continue;
        }

        if ( _bind( (SOCKET)sockfd, ai->ai_addr, ai->ai_addrlen ) )
		{
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in bind for %s", WSAGetLastError(), tcpAddress );
            WSAEventSelect( (SOCKET)sockfd, NULL, 0 );
            closesocket( (SOCKET)sockfd );
            WSACloseEvent( socketEvent );
            continue;
		}

        if ( _listen( (SOCKET)sockfd, SOMAXCONN ) )
		{
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in listen for %s", WSAGetLastError(), tcpAddress );
            WSAEventSelect( (SOCKET)sockfd, NULL, 0 );
            closesocket( (SOCKET)sockfd );
            WSACloseEvent( socketEvent );
            continue;
		}

        addr[0] = 0;
        if ( ai->ai_family == AF_INET )
        {
            struct sockaddr_in v4Address;
            int size = sizeof( v4Address );
            if ( getsockname( sockfd, (struct sockaddr*)&v4Address, &size ) )
            {
                WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in gestsockname for %s", WSAGetLastError(), tcpAddress );
                WSAEventSelect( (SOCKET)sockfd, NULL, 0 );
                closesocket( (SOCKET)sockfd );
                WSACloseEvent( socketEvent );
                continue;
            }

            pListener->port = ntohs( v4Address.sin_port );
            inet_ntop( ai->ai_family, &(v4Address.sin_addr), addr, sizeof( addr ) );
        }
        else
        {
            struct sockaddr_in6 v6Address;
            int size = sizeof( v6Address );
            if ( getsockname( sockfd, (struct sockaddr*)&v6Address, &size ) )
            {
                WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - error %i in gestsockname for %s", WSAGetLastError(), tcpAddress );
                WSAEventSelect( (SOCKET)sockfd, NULL, 0 );
                closesocket( (SOCKET)sockfd );
                WSACloseEvent( socketEvent );
                continue;
            }

            pListener->port = ntohs( v6Address.sin6_port );
            inet_ntop( ai->ai_family, &(v6Address.sin6_addr), addr, sizeof( addr ) );
        }
        pListener->address = _strdup( addr );
        if ( !pListener->address || !pListener->address[0] )
        {
            WLog_ERR( TAG, "freerdp_wds_prepare_reverse_connect - cant't address as string for %s", tcpAddress );
            WSAEventSelect( (SOCKET)sockfd, NULL, 0 );
            closesocket( (SOCKET)sockfd );
            WSACloseEvent( socketEvent );
            continue;
        }

		pListener->valid = TRUE;
		pListener->socket = sockfd;
		pListener->event = socketEvent;

        WLog_INFO( TAG, "freerdp_wds_prepare_reverse_connect - successfull listen on %s:%i for %s", pListener->address, pListener->port, tcpAddress );

		ctn->nbListeners++;
	}

	freeaddrinfo( res );
    return ctn->nbListeners;
}


FREERDP_LOCAL int freerdp_wds_connectionstring_fill_from_reverse_connection( rdpWdsConnectionstring* connectionString, const rdpWdsReverseConnection* connection )
{
	ReverseConnection* ctn = (ReverseConnection*)connection;
	if ( !ctn || !connectionString || !ctn->nbListeners )
		return -1;

	int* ports = calloc( ctn->nbListeners, sizeof( int ) );
	char** addresses = calloc( ctn->nbListeners, sizeof( char* ) );

	for ( int i = 0; i < ctn->nbListeners; i++ )
	{
		ports[i] = ctn->Listeners[i].port;
		addresses[i] = ctn->Listeners[i].address;
	}

	freerdp_wds_connectionstring_fill( connectionString, NULL, NULL, NULL, ctn->nbListeners, addresses, ports );

	free( ports );
	free( addresses );
	return 0;
}

FREERDP_LOCAL int freerdp_wds_wait_for_connect( rdpWdsReverseConnection* connection, HANDLE abortEvent )
{
#ifdef _WIN32
	u_long arg;
#endif

	ReverseConnection* ctn = (ReverseConnection*)connection;
	if ( !ctn  || !ctn->nbListeners )
		return -1;

	int nbEvents = ctn->nbListeners + ((abortEvent != NULL) ? 1 : 0);
	HANDLE* events = calloc( nbEvents, sizeof( HANDLE ) );
	for ( int i = 0; i < ctn->nbListeners; i++ )
	{
		events[i] = ctn->Listeners[i].event;
	}
    if ( NULL != abortEvent )
    {
        WLog_INFO( TAG, "freerdp_wds_wait_for_connect - called with %i listeners and abortEvent", ctn->nbListeners );
        events[nbEvents - 1] = abortEvent;
    }
    else
    {
        WLog_INFO( TAG, "freerdp_wds_wait_for_connect - called with %i listeners and without abortEvent", ctn->nbListeners );
    }

	DWORD status = WaitForMultipleObjects( nbEvents, events, FALSE, INFINITE );

    if ( status < WAIT_OBJECT_0 || status > WAIT_OBJECT_0 + nbEvents - 1 )
    {
        WLog_ERR( TAG, "freerdp_wds_wait_for_connect - error in WaitForMultipleObjects" );
        goto on_error; //any error
    }

    if ( (abortEvent != NULL) && (status == WAIT_OBJECT_0 + nbEvents - 1) )
    {
        WLog_WARN( TAG, "freerdp_wds_wait_for_connect - abort signaled" );
        goto on_error; //abort signalled
    }

    int idxSignaledListener = status - WAIT_OBJECT_0;

    WLog_INFO( TAG, "freerdp_wds_wait_for_connect - listener %i signalled %s:%i", idxSignaledListener + 1, ctn->Listeners[idxSignaledListener].address, ctn->Listeners[idxSignaledListener].port );

    Listener* pSignaledListener = &(ctn->Listeners[idxSignaledListener]);
	SOCKET clientSocket = accept( pSignaledListener->socket, NULL, NULL );
    if ( clientSocket == INVALID_SOCKET )
    {
        WLog_ERR( TAG, "freerdp_wds_wait_for_connect - clientsocket %i error %i in accept", idxSignaledListener + 1, WSAGetLastError() );
        goto on_error;
    }

    WLog_INFO( TAG, "freerdp_wds_wait_for_connect - clientsocket %i accepted", idxSignaledListener + 1 );

	/* set socket in blocking mode */
	if ( WSAEventSelect( clientSocket, NULL, 0 ) )
	{
		closesocket( clientSocket );
        WLog_ERR( TAG, "freerdp_wds_wait_for_connect - clientsocket %i error %i in WSAEventSelect", idxSignaledListener + 1, WSAGetLastError() );
		goto on_error;
	}

    WLog_INFO( TAG, "freerdp_wds_wait_for_connect - clientsocket %i WSAEventSelect called", idxSignaledListener + 1 );

#ifndef _WIN32
	fcntl( sockfd, F_SETFL, O_NONBLOCK );
#else
	arg = 0;
	if ( ioctlsocket( clientSocket, FIONBIO, &arg ) )
        WLog_ERR( TAG, "freerdp_wds_wait_for_connect - clientsocket %i error %i set blocking mode on", idxSignaledListener + 1, WSAGetLastError() );
    else
        WLog_INFO( TAG, "freerdp_wds_wait_for_connect - clientsocket %i set blocking mode on", idxSignaledListener + 1 );
#endif


	ctn->clientSocket = clientSocket;
	free( events );

    if ( !(ctn->listenerDisconnectThread = CreateThread( NULL, 0, (LPTHREAD_START_ROUTINE)freerdp_listener_disconnect_thread,
        ctn, 0, NULL )) )
    {
        WLog_ERR( TAG, "Failed to create listener disconnect thread" );
        freerdp_wds_listener_disconnect( ctn );
    }

    if ( abortEvent != NULL )
    {
        if ( WAIT_OBJECT_0 == WaitForSingleObject( abortEvent, 0 ) )
        {
            WLog_WARN( TAG, "freerdp_wds_wait_for_connect - clientsocket %i abort signaled in end of function", idxSignaledListener + 1 );
            return -1;
        }
    }

    union
    {
        struct sockaddr address;
        struct sockaddr_in v4Address;
        struct sockaddr_in6 v6Address;
    } localAddress, remoteAddress;

    int localAddressSize = sizeof( localAddress );
    int remoteAddressSize = sizeof( remoteAddress );

    BOOL localFound = 0 == getsockname( clientSocket, (struct sockaddr*)&localAddress, &localAddressSize );
    BOOL remoteFound = 0 == getpeername( clientSocket, (struct sockaddr*)&remoteAddress, &remoteAddressSize );

    char strLocal[99] = "";
    int  portLocal = 0;
    if ( localFound )
    {
        portLocal = ntohs( localAddress.address.sa_family == AF_INET ? localAddress.v4Address.sin_port : localAddress.v6Address.sin6_port );
        inet_ntop( localAddress.address.sa_family, localAddress.address.sa_family == AF_INET ? (PVOID*)&localAddress.v4Address.sin_addr : (PVOID*)&localAddress.v6Address.sin6_addr, strLocal, sizeof( strLocal ) );
    }

    char strRemote[99] = "";
    int  portRemote = 0;
    if ( remoteFound )
    {
        portRemote = ntohs( remoteAddress.address.sa_family == AF_INET ? remoteAddress.v4Address.sin_port : remoteAddress.v6Address.sin6_port );
        inet_ntop( remoteAddress.address.sa_family, remoteAddress.address.sa_family == AF_INET ? (PVOID*)&remoteAddress.v4Address.sin_addr : (PVOID*)&remoteAddress.v6Address.sin6_addr, strRemote, sizeof( strRemote ) );
    }

    WLog_INFO( TAG, "freerdp_wds_wait_for_connect - clientsocket %i ready local %s:%i remote %s:%i", idxSignaledListener + 1, strLocal, portLocal, strRemote, portRemote );
	return 0;

on_error:
	free( events );
	return -1;
}


FREERDP_LOCAL int freerdp_wds_update_settings_after_reverse_connect( rdpWdsReverseConnection* connection, rdpSettings* settings )
{
	ReverseConnection* ctn = (ReverseConnection*)connection;
	if ( !ctn || !settings )
		return -1;

	if ( INVALID_SOCKET == ctn->clientSocket )
		return -1;

	if ( freerdp_set_param_string( settings, FreeRDP_ServerHostname, "|" ) != 0 )
		return -1;
	freerdp_set_param_uint32( settings, FreeRDP_ServerPort, ctn->clientSocket );

    freerdp_set_param_bool( settings, FreeRDP_RdpSecurity, TRUE );
	freerdp_set_param_bool( settings, FreeRDP_TlsSecurity, FALSE );
	freerdp_set_param_bool( settings, FreeRDP_NlaSecurity, FALSE );
	freerdp_set_param_bool( settings, FreeRDP_ExtSecurity, FALSE );
	freerdp_set_param_bool( settings, FreeRDP_NegotiateSecurityLayer, TRUE );
    freerdp_set_param_bool( settings, FreeRDP_SendPreconnectionPdu, FALSE );
    return 0;
}


static void freerdp_wds_listener_disconnect( ReverseConnection* ctn )
{
    if ( !ctn || !ctn->nbListeners )
        return;

    WLog_INFO( TAG, "freerdp_wds_listener_disconnect - start closing all listener" );
    for ( int i = 0; i < ctn->nbListeners; i++ )
    {
        if ( ctn->Listeners[i].valid )
        {
            WLog_INFO( TAG, "freerdp_wds_listener_disconnect - listener %i start closing %s:%i", i + 1, ctn->Listeners[i].address, ctn->Listeners[i].port );

            if ( WSAEventSelect( ctn->Listeners[i].socket, NULL, 0 ) )
                WLog_ERR( TAG, "freerdp_wds_listener_disconnect - listener %i error %i in WSAEventSelect %s:%i", i + 1, WSAGetLastError(), ctn->Listeners[i].address, ctn->Listeners[i].port );
            else
                WLog_INFO( TAG, "freerdp_wds_listener_disconnect - listener %i WSAEventSelect done %s:%i", i + 1, ctn->Listeners[i].address, ctn->Listeners[i].port );
            if ( closesocket( ctn->Listeners[i].socket ) )
                WLog_ERR( TAG, "freerdp_wds_listener_disconnect - listener %i error %i in closesocket %s:%i", i + 1, WSAGetLastError(), ctn->Listeners[i].address, ctn->Listeners[i].port );
            else
                WLog_INFO( TAG, "freerdp_wds_listener_disconnect - listener %i closesocket done %s:%i", i + 1, ctn->Listeners[i].address, ctn->Listeners[i].port );
            if ( !WSACloseEvent( ctn->Listeners[i].event ) )
                WLog_ERR( TAG, "freerdp_wds_listener_disconnect - listener %i error %i in WSACloseEvent %s:%i", i + 1, WSAGetLastError(), ctn->Listeners[i].address, ctn->Listeners[i].port );
            else
                WLog_INFO( TAG, "freerdp_wds_listener_disconnect - listener %i WSACloseEvent done %s:%i", i + 1, ctn->Listeners[i].address, ctn->Listeners[i].port );

            WLog_INFO( TAG, "freerdp_wds_listener_disconnect - listener %i closed %s:%i", i + 1, ctn->Listeners[i].address, ctn->Listeners[i].port );
            ctn->Listeners[i].valid = FALSE;
        }
    }
    WLog_INFO( TAG, "freerdp_wds_listener_disconnect - all listener closed" );

    free( ctn->Listeners );
    ctn->Listeners = NULL;
    ctn->nbListeners = 0;
}

static void* freerdp_listener_disconnect_thread( void* arg )
{
    ReverseConnection* ctn = (ReverseConnection*)arg;
    WLog_INFO( TAG, "freerdp_listener_disconnect_thread - started" );
    freerdp_wds_listener_disconnect( ctn );
    WLog_INFO( TAG, "freerdp_listener_disconnect_thread - finished" );
    ExitThread( 0 );
    return NULL;
}
